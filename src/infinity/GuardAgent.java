package infinity;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Infinity Guard — in-process integrity agent.
 *
 * Two cooperating threads:
 *   1. pack monitor   — local, fast: deletes unauthorized resource packs on disk
 *                       and reports them to /api/launcher/report-violation.
 *   2. attestation    — proves liveness to the server with a rolling HMAC
 *                       heartbeat (init → beat → end).  If the heartbeat stops,
 *                       the server's sweeper kicks the player.  This makes the
 *                       lock fail-closed: blocking the endpoint or killing the
 *                       JVM results in a kick instead of a free pass.
 */
public class GuardAgent {
    private static final Set<String>    whitelist    = new HashSet<>();    // allowed resource-pack sha1s
    private static final Set<String>    modWhitelist = new HashSet<>();    // allowed mod sha1s
    private static final Set<String>    reported     = new HashSet<>();   // avoid duplicate reports
    private static final Map<String, long[]> pending = new HashMap<>();   // stability tracker

    /** A file must be size-stable for this many ms before we hash it. */
    private static final long STABLE_MS = 600;

    private static final File RP_DIR   = new File("resourcepacks");
    private static final File MODS_DIR = new File("mods");

    private static volatile boolean running = true;

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[Infinity Guard] Agent loaded — enforcing resource pack + mod whitelist.");

        loadHashes(System.getProperty("infinity.whitelist"), whitelist);
        loadHashes(System.getProperty("infinity.mod_whitelist"), modWhitelist);
        System.out.println("[Infinity Guard] Loaded " + whitelist.size()
            + " pack hash(es), " + modWhitelist.size() + " mod hash(es).");

        // Scan mods/ synchronously BEFORE returning — premain runs before the
        // Fabric mod loader, so an unauthorized jar injected after sync (TOCTOU)
        // is caught here before it can load.
        scanModsOnce();

        startPackMonitor();
        startAttestation();
    }

    private static void loadHashes(String prop, Set<String> into) {
        if (prop == null || prop.trim().isEmpty()) return;
        for (String hash : prop.split(",")) {
            String trimmed = hash.trim().toLowerCase();
            if (!trimmed.isEmpty()) into.add(trimmed);
        }
    }

    /** One-shot startup scan of mods/ — reports any jar not in the whitelist. */
    private static void scanModsOnce() {
        if (modWhitelist.isEmpty()) return; // nothing to enforce against
        if (!MODS_DIR.exists() || !MODS_DIR.isDirectory()) return;
        File[] files = MODS_DIR.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (!isModFile(f)) continue;
            String key = f.getAbsolutePath();
            if (reported.contains(key)) continue;
            String hash = sha1(f);
            if (!hash.isEmpty() && !modWhitelist.contains(hash)) {
                reportModViolation(f.getName(), hash);
                reported.add(key);
            }
        }
    }

    private static boolean isModFile(File f) {
        if (!f.isFile()) return false;
        String name = f.getName().toLowerCase();
        // .jar and .jar.disabled both load-relevant; ignore everything else.
        return name.endsWith(".jar");
    }

    // ====================================================================
    //  Thread 1 — local resource-pack monitor
    // ====================================================================

    private static void startPackMonitor() {
        Thread monitor = new Thread(() -> {
            File optionsFile = new File("options.txt");

            while (running) {
                try {
                    Thread.sleep(100);

                    // --- 1. Scan resourcepacks/ directory ---
                    if (RP_DIR.exists() && RP_DIR.isDirectory()) {
                        File[] files = RP_DIR.listFiles();
                        if (files != null) {
                            for (File file : files) {
                                if (!isPackFile(file)) continue;

                                String key  = file.getAbsolutePath();
                                long   size = file.length();
                                long   now  = System.currentTimeMillis();

                                long[] state = pending.get(key);
                                if (state == null) {
                                    pending.put(key, new long[]{ size, now });
                                    continue;
                                }
                                if (state[0] != size) {
                                    state[0] = size;
                                    state[1] = now;
                                    continue;
                                }
                                if (now - state[1] < STABLE_MS) continue;

                                // File is stable — safe to hash
                                pending.remove(key);

                                if (reported.contains(key)) continue; // already handled

                                String hash = sha1(file);
                                if (!hash.isEmpty() && !whitelist.contains(hash)) {
                                    reportViolation(file.getName(), hash, "unauthorized_resource_pack_file");
                                    reported.add(key); // don't re-report on next tick
                                }
                            }

                            // Clean stale tracking entries for removed files
                            pending.keySet().removeIf(k -> !new File(k).exists());
                            reported.removeIf(k -> !new File(k).exists());
                        }
                    }

                    // --- 2. options.txt sanity check ---
                    if (optionsFile.exists()) {
                        checkOptionsFile(optionsFile);
                    }

                    // --- 3. Re-scan mods/ for jars dropped in after startup ---
                    scanModsOnce();

                } catch (InterruptedException e) {
                    break;
                } catch (Exception ignored) {
                    // Keep guard alive regardless
                }
            }
        });
        monitor.setDaemon(true);
        monitor.setName("infinity-guard-monitor");
        monitor.start();
    }

    // ====================================================================
    //  Thread 2 — server attestation heartbeat
    // ====================================================================

    private static void startAttestation() {
        final String serverUrl = System.getProperty("infinity.server_url");
        final String token      = System.getProperty("infinity.token");

        if (serverUrl == null || serverUrl.isEmpty() || token == null || token.isEmpty()) {
            System.err.println("[Infinity Guard] No server credentials — attestation disabled.");
            return;
        }
        final String base = serverUrl.replaceAll("/$", "");

        Thread beat = new Thread(() -> {
            // --- init (retry on transient network errors) ---
            String secret = null, nonce = null;
            long intervalMs = 5000;
            for (int attempt = 0; attempt < 5 && running; attempt++) {
                try {
                    String body = "{\"packHashes\":" + hashesToJson(currentPackHashes()) + "}";
                    HttpResult res = post(base + "/api/launcher/attest/init", token, body);
                    if (res.status == 200) {
                        secret     = extractString(res.body, "secret");
                        nonce      = extractString(res.body, "nonce");
                        long iv    = extractLong(res.body, "intervalMs");
                        if (iv > 0) intervalMs = iv;
                        break;
                    }
                    if (res.status == 401 || res.status == 403) {
                        System.err.println("[Infinity Guard] Attestation init rejected (HTTP "
                            + res.status + "). Server will handle the kick.");
                        return;
                    }
                } catch (Exception e) {
                    // network hiccup — back off and retry
                }
                sleep(2000);
            }

            if (secret == null || nonce == null) {
                System.err.println("[Infinity Guard] Attestation init failed — no heartbeat.");
                return;
            }
            System.out.println("[Infinity Guard] Attestation established (interval " + intervalMs + "ms).");

            // Clean shutdown → tell the server so the sweeper won't kick.
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try { post(base + "/api/launcher/attest/end", token, "{}"); } catch (Exception ignored) {}
            }));

            // --- beat loop ---
            int counter = 0;
            while (running) {
                sleep(intervalMs);
                try {
                    counter++;
                    List<String> hashes = currentPackHashes();
                    String mac  = hmac(secret, counter, nonce, hashes);
                    String body = "{\"counter\":" + counter
                                + ",\"mac\":\"" + mac + "\""
                                + ",\"packHashes\":" + hashesToJson(hashes) + "}";

                    HttpResult res = post(base + "/api/launcher/attest/beat", token, body);
                    if (res.status == 200) {
                        String next = extractString(res.body, "nonce");
                        if (next != null && !next.isEmpty()) nonce = next;
                        long iv = extractLong(res.body, "intervalMs");
                        if (iv > 0) intervalMs = iv;
                    } else if (res.status == 403 || res.status == 409) {
                        // Server rejected us — it has (or will) kick. Stop beating.
                        System.err.println("[Infinity Guard] Heartbeat rejected (HTTP "
                            + res.status + "). Stopping.");
                        return;
                    }
                    // Other statuses / network errors: keep trying; the server's
                    // grace window tolerates a few misses before the sweeper acts.
                } catch (Exception e) {
                    // transient — retry on the next tick
                }
            }
        });
        beat.setDaemon(true);
        beat.setName("infinity-guard-attest");
        beat.start();
    }

    // ====================================================================
    //  Violation reporting (local fast-path)
    // ====================================================================

    /**
     * Deletes the offending file and notifies the server, which kicks via RCON.
     */
    private static void reportViolation(String packName, String packHash, String reason) {
        System.err.println(
            "[Infinity Guard] VIOLATION — pack: " + packName + " (sha1: " + packHash + ")"
        );

        // Remove the file immediately so Minecraft can't read more data from it
        File packFile = new File(RP_DIR, packName);
        if (packFile.exists()) {
            if (packFile.delete()) {
                System.err.println("[Infinity Guard] Pack file deleted: " + packName);
            } else {
                System.err.println("[Infinity Guard] WARNING: Could not delete: " + packName);
            }
        }

        String serverUrl = System.getProperty("infinity.server_url");
        String token     = System.getProperty("infinity.token");
        if (serverUrl == null || serverUrl.isEmpty() || token == null || token.isEmpty()) {
            System.err.println("[Infinity Guard] No server credentials — cannot report violation.");
            return;
        }

        try {
            String endpoint = serverUrl.replaceAll("/$", "") + "/api/launcher/report-violation";
            String payload  = "{\"packName\":\"" + escapeJson(packName)
                            + "\",\"packHash\":\"" + escapeJson(packHash)
                            + "\",\"reason\":\"" + escapeJson(reason) + "\"}";
            HttpResult res = post(endpoint, token, payload);
            System.err.println("[Infinity Guard] Server notified (HTTP " + res.status
                + ") — server will kick the player.");
        } catch (Exception e) {
            System.err.println("[Infinity Guard] Failed to reach server: " + e.getMessage());
        }
    }

    /**
     * Reports an unauthorized mod. Unlike resource packs, a mod jar is already
     * loaded (and often OS-locked) by the time we see it, so deleting it is
     * futile — we rely on the server to kick via RCON.
     */
    private static void reportModViolation(String modName, String modHash) {
        System.err.println(
            "[Infinity Guard] VIOLATION — mod: " + modName + " (sha1: " + modHash + ")"
        );

        String serverUrl = System.getProperty("infinity.server_url");
        String token     = System.getProperty("infinity.token");
        if (serverUrl == null || serverUrl.isEmpty() || token == null || token.isEmpty()) {
            System.err.println("[Infinity Guard] No server credentials — cannot report mod violation.");
            return;
        }

        try {
            String endpoint = serverUrl.replaceAll("/$", "") + "/api/launcher/report-violation";
            // Reuse the existing endpoint shape; packName carries the mod name.
            String payload  = "{\"packName\":\"" + escapeJson(modName)
                            + "\",\"packHash\":\"" + escapeJson(modHash)
                            + "\",\"reason\":\"unauthorized_mod\"}";
            HttpResult res = post(endpoint, token, payload);
            System.err.println("[Infinity Guard] Server notified of mod violation (HTTP "
                + res.status + ") — server will kick the player.");
        } catch (Exception e) {
            System.err.println("[Infinity Guard] Failed to reach server: " + e.getMessage());
        }
    }

    // ====================================================================
    //  Helpers
    // ====================================================================

    private static boolean isPackFile(File f) {
        String name = f.getName().toLowerCase();
        if (name.equals(".ds_store") || name.equals("desktop.ini")) return false;
        if (f.isFile() && (name.endsWith(".zip") || name.endsWith(".jar"))) return true;
        if (f.isDirectory() && new File(f, "pack.mcmeta").exists()) return true;
        return false;
    }

    /** SHA-1 of every pack file currently in resourcepacks/ (lowercase hex). */
    private static List<String> currentPackHashes() {
        List<String> out = new ArrayList<>();
        if (RP_DIR.exists() && RP_DIR.isDirectory()) {
            File[] files = RP_DIR.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (!isPackFile(f) || f.isDirectory()) continue;
                    String h = sha1(f);
                    if (!h.isEmpty()) out.add(h);
                }
            }
        }
        return out;
    }

    private static void checkOptionsFile(File optionsFile) throws Exception {
        if (whitelist.isEmpty()) return;

        String content = new String(Files.readAllBytes(optionsFile.toPath()), "UTF-8");
        for (String line : content.split("\\r?\\n")) {
            if (!line.startsWith("resourcePacks:") && !line.startsWith("incompatibleResourcePacks:"))
                continue;

            int start = line.indexOf('[');
            int end   = line.lastIndexOf(']');
            if (start < 0 || end < 0 || end <= start) continue;

            String inner = line.substring(start + 1, end);
            for (String token : inner.split(",")) {
                String entry = token.trim().replaceAll("^\"|\"$", "");
                if (!entry.startsWith("file/")) continue;

                String filename = entry.substring("file/".length());
                File   packFile = new File(RP_DIR, filename);
                if (!packFile.exists()) continue;

                String key  = packFile.getAbsolutePath();
                long   size = packFile.length();
                long   now  = System.currentTimeMillis();

                long[] state = pending.get(key);
                if (state != null && (state[0] != size || now - state[1] < STABLE_MS)) continue;
                if (reported.contains(key)) continue;

                String hash = sha1(packFile);
                if (!hash.isEmpty() && !whitelist.contains(hash)) {
                    reportViolation(filename, hash, "unauthorized_pack_in_options");
                    reported.add(key);
                }
            }
        }
    }

    private static String sha1(File file) {
        try (InputStream is = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] buf = new byte[8192];
            int read;
            while ((read = is.read(buf)) > 0) digest.update(buf, 0, read);
            byte[] hash = digest.digest();
            StringBuilder sb = new StringBuilder(40);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * HMAC-SHA256 over "counter:nonce:h1,h2,...".  Hashes are lowercased and
     * sorted so the agent and server agree regardless of directory order.
     * Must stay byte-for-byte identical to the server's expectedMac().
     */
    private static String hmac(String secretHex, int counter, String nonce, List<String> hashes)
            throws Exception {
        List<String> h = new ArrayList<>(hashes);
        for (int i = 0; i < h.size(); i++) h.set(i, h.get(i).toLowerCase());
        Collections.sort(h);
        String payload = counter + ":" + nonce + ":" + String.join(",", h);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hexToBytes(secretHex), "HmacSHA256"));
        byte[] out = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(out.length * 2);
        for (byte b : out) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String hashesToJson(List<String> hashes) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < hashes.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(hashes.get(i))).append("\"");
        }
        return sb.append("]").toString();
    }

    // --- tiny HTTP + JSON (no external deps) ---

    private static final class HttpResult {
        final int status;
        final String body;
        HttpResult(int status, String body) { this.status = status; this.body = body; }
    }

    private static HttpResult post(String endpoint, String token, String json) throws Exception {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }
        int status = conn.getResponseCode();
        InputStream is = (status >= 200 && status < 400) ? conn.getInputStream() : conn.getErrorStream();
        String body = "";
        if (is != null) {
            body = new String(readAll(is), StandardCharsets.UTF_8);
            is.close();
        }
        conn.disconnect();
        return new HttpResult(status, body);
    }

    private static byte[] readAll(InputStream is) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    private static String extractString(String json, String key) {
        if (json == null) return null;
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static long extractLong(String json, String key) {
        if (json == null) return -1;
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)").matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { running = false; }
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
