package com.example.saslinkerjava;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.Executors;

import com.google.zxing.*;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

public class SASLinker {

    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
    private static final BigInteger G = BigInteger.valueOf(2);

    private static BigInteger privateKey;
    private static BigInteger publicKey;
    private static String randomNonce;

    private static volatile String expectedSAS;
    private static volatile boolean verified = false;   // phone entered correct SAS
    private static volatile boolean confirmed = false;  // desktop accepted
    private static volatile boolean rejected  = false;  // desktop rejected

    public static void main(String[] args) {
        try {
            generateDHKeyPair();
            generateQRCode();
            startHttpServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateDHKeyPair() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        privateKey = new BigInteger(2048, random).mod(P);
        publicKey = G.modPow(privateKey, P);

        byte[] nonceBytes = new byte[16];
        random.nextBytes(nonceBytes);
        randomNonce = Base64.getEncoder().encodeToString(nonceBytes);

        System.out.println("\nPublic Key (first 32 hex): " + publicKey.toString(16).substring(0, 32) + "...");
        System.out.println("Random Nonce: " + randomNonce);
    }

    private static void generateQRCode() throws Exception {
        String data = publicKey.toString() + ":" + randomNonce; // Flutter already understands this format
        BitMatrix matrix = new QRCodeWriter().encode(data, BarcodeFormat.QR_CODE, 300, 300);
        File file = new File("sas_qr.png");
        MatrixToImageWriter.writeToPath(matrix, "PNG", file.toPath());
        System.out.println("\nQR saved to sas_qr.png. Open http://localhost:8889 in your browser.");
    }

    private static void startHttpServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8889), 0);

        // ---------- Web UI ----------
        server.createContext("/", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())) { respond(exchange, 405, ""); return; }
            byte[] html = INDEX_HTML.getBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, html.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(html); }
        });

        server.createContext("/qr.png", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())) { respond(exchange, 405, ""); return; }
            File qr = new File("sas_qr.png");
            if (!qr.exists()) { respond(exchange, 404, "QR not found"); return; }
            exchange.getResponseHeaders().set("Content-Type", "image/png");
            exchange.sendResponseHeaders(200, qr.length());
            try (OutputStream os = exchange.getResponseBody()) { Files.copy(qr.toPath(), os); }
        });

        server.createContext("/state", exchange -> {
            if (!"GET".equals(exchange.getRequestMethod())) { respond(exchange, 405, ""); return; }
            String status;
            if (rejected) {
                status = "rejected";
            } else if (confirmed) {
                status = "accepted";
            } else if (verified) {
                status = "awaiting"; // SAS matched, waiting for Accept/Reject
            } else if (expectedSAS != null) {
                status = "pending";  // QR scanned and /start called, waiting for SAS on phone
            } else {
                status = "idle";     // initial
            }
            String json = "{\"status\":\"" + status + "\"}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            respond(exchange, 200, json);
        });

        // ---------- Mobile endpoints ----------
        server.createContext("/start", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try (InputStream is = exchange.getRequestBody()) {
                    String body = readRequestBody(is);
                    String[] parts = body.split(":");
                    if (parts.length != 2) { respond(exchange, 400, "Invalid input format."); return; }

                    BigInteger clientPub = new BigInteger(parts[0]);
                    String clientNonce = parts[1];

                    BigInteger sharedSecret = clientPub.modPow(privateKey, P);
                    expectedSAS = computeSAS(sharedSecret.toString(), randomNonce, clientNonce);

                    // reset state for new session
                    verified = false;
                    confirmed = false;
                    rejected = false;

                    System.out.println("\nSAS generated: " + expectedSAS);
                    respond(exchange, 200, expectedSAS);
                } catch (Exception e) {
                    respond(exchange, 500, "Error processing request: " + e.getMessage());
                }
            } else {
                respond(exchange, 405, "");
            }
        });

        server.createContext("/verify", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try (InputStream is = exchange.getRequestBody()) {
                    String enteredSAS = readRequestBody(is);
                    System.out.println("\nSAS entered: " + enteredSAS);

                    if (expectedSAS != null && expectedSAS.equals(enteredSAS)) {
                        verified = true;
                        respond(exchange, 200, "✅ SAS Matched. Awaiting confirmation...");
                    } else {
                        respond(exchange, 200, "❌ SAS Mismatch. Authentication failed.");
                    }
                } catch (Exception e) {
                    respond(exchange, 500, "Error verifying SAS: " + e.getMessage());
                }
            } else {
                respond(exchange, 405, "");
            }
        });

        // Called by the web page buttons
        server.createContext("/confirm", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                String body = readRequestBody(exchange.getRequestBody()).trim().toLowerCase();
                if ("accept".equals(body)) {
                    confirmed = true; rejected = false;
                    respond(exchange, 200, "accepted");
                } else if ("reject".equals(body)) {
                    confirmed = false; rejected = true;
                    respond(exchange, 200, "rejected");
                } else {
                    respond(exchange, 400, "unknown");
                }
            } else {
                respond(exchange, 405, "");
            }
        });

        // Flutter polls this to close its waiting dialog
        server.createContext("/poll", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                if (confirmed)      respond(exchange, 200, "accepted");
                else if (rejected)  respond(exchange, 200, "rejected");
                else                respond(exchange, 200, "waiting");
            } else {
                respond(exchange, 405, "");
            }
        });

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("\nHTTP server on http://localhost:8889  (open in your desktop browser)");
    }

    private static String readRequestBody(InputStream is) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(is));
        StringBuilder b = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null) b.append(line);
        return b.toString();
    }

    private static String computeSAS(String sharedSecret, String nonceA, String nonceB) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String combined = sharedSecret + nonceA + nonceB;
        byte[] hash = digest.digest(combined.getBytes());
        String base64 = Base64.getEncoder().encodeToString(hash);
        return base64.replaceAll("[^A-Za-z0-9]", "").substring(0, 6);
    }

    private static void respond(HttpExchange exchange, int code, String response) throws IOException {
        byte[] bytes = response.getBytes();
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
    }

    // ---- Web UI with state-driven visibility changes ----
    private static final String INDEX_HTML =
            "<!doctype html>\n" +
                    "<html lang='en'>\n" +
                    "<head>\n" +
                    "  <meta charset='utf-8'>\n" +
                    "  <meta name='viewport' content='width=device-width, initial-scale=1'>\n" +
                    "  <title>SASLinker Desktop</title>\n" +
                    "  <style>\n" +
                    "    :root{--bg:#111b21;--panel:#202c33;--muted:#aebac1;--primary:#25d366}\n" +
                    "    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:#e9edef}\n" +
                    "    .wrap{display:flex;min-height:100vh}\n" +
                    "    .left{flex:1;background:#0b141a;display:flex;align-items:center;justify-content:center;padding:24px}\n" +
                    "    .card{background:var(--panel);border-radius:16px;padding:24px;box-shadow:0 6px 24px rgba(0,0,0,.35);width:860px;max-width:92vw}\n" +
                    "    .grid{display:grid;grid-template-columns:320px 1fr;gap:28px;align-items:start}\n" +
                    "    .title{font-size:22px;font-weight:700;margin-bottom:6px}\n" +
                    "    .sub{font-size:13px;color:var(--muted);margin-bottom:16px}\n" +
                    "    .qr{width:280px;height:280px;border-radius:12px;background:#111;display:block;margin:0 auto 8px auto}\n" +
                    "    .status{margin-top:8px;font-size:13px;color:var(--muted);text-align:center}\n" +
                    "    .chip{display:inline-block;padding:6px 10px;border-radius:999px;background:#0b3d2e;color:#59f1a8;font-weight:600;font-size:12px;margin:8px auto 0 auto}\n" +
                    "    .actions{margin-top:14px;display:none;gap:12px;justify-content:center}\n" +
                    "    .btn{border:0;border-radius:10px;padding:10px 14px;cursor:pointer;font-weight:600}\n" +
                    "    .btn-accept{background:var(--primary);color:#062f1a}\n" +
                    "    .btn-reject{background:#ef5350;color:#2b1110}\n" +
                    "    .instructions{text-align:left;font-size:14px;color:#d1d7db;line-height:1.55}\n" +
                    "    .instructions h2{font-size:16px;margin:0 0 10px 0}\n" +
                    "    .instructions ol{padding-left:20px;margin:0}\n" +
                    "    .instructions li{margin-bottom:8px}\n" +
                    "    .note{font-size:13px;color:var(--muted);margin-top:10px}\n" +
                    "    .sep{height:1px;background:#2b3940;margin:16px 0}\n" +
                    "    .hidden{display:none !important}\n" +
                    "    .center{ text-align:center }\n" +
                    "    .big-welcome{font-size:28px;font-weight:800;margin:8px 0 0 0}\n" +
                    "    .warning{font-size:18px;font-weight:700;color:#ffb3b3}\n" +
                    "  </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "  <div class='wrap'>\n" +
                    "    <div class='left'>\n" +
                    "      <div class='card'>\n" +
                    "        <div class='title'>Link a device</div>\n" +
                    "        <div class='sub'>Use your phone to scan this code and complete a secure link.</div>\n" +
                    "\n" +
                    "        <div id='qrBlock' class='grid'>\n" +
                    "          <div>\n" +
                    "            <img class='qr' src='/qr.png' alt='QR code'>\n" +
                    "            <div class='status' id='status'>Waiting for scan…</div>\n" +
                    "          </div>\n" +
                    "          <div class='instructions'>\n" +
                    "            <h2>To link your phone:</h2>\n" +
                    "            <ol>\n" +
                    "              <li>Open <strong>SASLinker</strong> on your phone.</li>\n" +
                    "              <li>Tap <strong>Scan QR</strong> (or <em>Start Linking</em>).</li>\n" +
                    "              <li>Point your phone camera at this screen to scan the QR.</li>\n" +
                    "              <li>On your phone, a <strong>6-digit SAS code</strong> will appear. Enter it and submit.</li>\n" +
                    "              <li>If the code matches, this page will ask you to <strong>Accept</strong> the link.</li>\n" +
                    "            </ol>\n" +
                    "            <div class='sep'></div>\n" +
                    "            <p class='note'>If the SAS code does <strong>not</strong> match on both devices, reject the linking from your phone or here.</p>\n" +
                    "          </div>\n" +
                    "        </div>\n" +
                    "\n" +
                    "        <div id='actionsBlock' class='center hidden'>\n" +
                    "          <div class='chip' id='chip'>SAS matched — awaiting confirmation</div>\n" +
                    "          <div class='actions' id='actions' style='display:flex;justify-content:center;gap:12px;margin-top:14px'>\n" +
                    "            <button class='btn btn-accept' onclick='confirmAction(\"accept\")'>Accept</button>\n" +
                    "            <button class='btn btn-reject' onclick='confirmAction(\"reject\")'>Reject</button>\n" +
                    "          </div>\n" +
                    "        </div>\n" +
                    "\n" +
                    "        <div id='resultBlock' class='center hidden'>\n" +
                    "          <div id='welcome' class='big-welcome hidden'>🎉 Authentication successful — Welcome!</div>\n" +
                    "          <div id='warning' class='warning hidden'>⚠️ Authentication rejected. Please try again or verify the SAS.</div>\n" +
                    "        </div>\n" +
                    "\n" +
                    "      </div>\n" +
                    "    </div>\n" +
                    "  </div>\n" +
                    "\n" +
                    "  <script>\n" +
                    "    const qrBlock = document.getElementById('qrBlock');\n" +
                    "    const actionsBlock = document.getElementById('actionsBlock');\n" +
                    "    const resultBlock = document.getElementById('resultBlock');\n" +
                    "    const statusEl = document.getElementById('status');\n" +
                    "    const welcome = document.getElementById('welcome');\n" +
                    "    const warning = document.getElementById('warning');\n" +
                    "\n" +
                    "    function show(el){ el.classList.remove('hidden'); }\n" +
                    "    function hide(el){ el.classList.add('hidden'); }\n" +
                    "\n" +
                    "    async function poll(){\n" +
                    "      try{\n" +
                    "        const r = await fetch('/state',{cache:'no-store'});\n" +
                    "        const j = await r.json();\n" +
                    "        const s = j.status;\n" +
                    "\n" +
                    "        if(s==='idle'){\n" +
                    "          show(qrBlock); hide(actionsBlock); hide(resultBlock);\n" +
                    "          statusEl.textContent = 'Waiting for scan…';\n" +
                    "        }\n" +
                    "        else if(s==='pending'){\n" +
                    "          // QR scanned; hide QR + instructions, show neutral waiting message\n" +
                    "          hide(qrBlock); hide(actionsBlock); hide(resultBlock);\n" +
                    "          // Create a temporary message using the card subtitle area\n" +
                    "          statusEl.textContent = 'Waiting for phone to verify SAS…';\n" +
                    "        }\n" +
                    "        else if(s==='awaiting'){\n" +
                    "          // SAS matched; show Accept/Reject, keep QR/instructions hidden\n" +
                    "          hide(qrBlock); hide(resultBlock); show(actionsBlock);\n" +
                    "        }\n" +
                    "        else if(s==='accepted'){\n" +
                    "          hide(qrBlock); hide(actionsBlock); show(resultBlock);\n" +
                    "          warning.classList.add('hidden');\n" +
                    "          welcome.classList.remove('hidden');\n" +
                    "        }\n" +
                    "        else if(s==='rejected'){\n" +
                    "          hide(qrBlock); hide(actionsBlock); show(resultBlock);\n" +
                    "          welcome.classList.add('hidden');\n" +
                    "          warning.classList.remove('hidden');\n" +
                    "        }\n" +
                    "      }catch(e){ /* ignore transient errors */ }\n" +
                    "    }\n" +
                    "\n" +
                    "    async function confirmAction(choice){\n" +
                    "      await fetch('/confirm',{method:'POST',headers:{'Content-Type':'text/plain'},body:choice});\n" +
                    "      await poll();\n" +
                    "    }\n" +
                    "\n" +
                    "    setInterval(poll, 800);\n" +
                    "    poll();\n" +
                    "  </script>\n" +
                    "</body>\n" +
                    "</html>";
}
