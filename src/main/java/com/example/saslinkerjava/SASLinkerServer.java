// File: SASLinkerServer.java
// Secondary Device (desktop) hardened server.
// Endpoints: /pd_init, /pd_reveal, /pd_verify, /sd_local_check, /confirm
// Defenses: PD HMAC proof (bound to DH + nonces + transcript) + SD local last-2 check + short TTL

package com.example.saslinkerjava;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;

public class SASLinkerServer {

    // 2048-bit safe prime (same as you used)
    private static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
    private static final BigInteger G = BigInteger.valueOf(2);

    private static final SecureRandom RNG = new SecureRandom();
    private static final Duration SESSION_TTL = Duration.ofSeconds(45);

    static class Session {
        String sid;
        BigInteger sdPriv, sdPub;
        byte[] rSD;                 // 16 bytes
        String cSDHex;              // SHA256(rSD || sdPub-decimal)

        BigInteger pdPub;           // set by /pd_init
        String cPDHex;              // set by /pd_init
        byte[] rPD;                 // set by /pd_reveal

        byte[] hmacKey;             // first 32 bytes of SHA256(sharedSecret-decimal)
        String sas;                 // 6 chars A–Z0–9

        boolean pdProofOK = false;  // after /pd_verify
        boolean sdLocalOK = false;  // after /sd_local_check
        boolean accepted = false;
        boolean rejected = false;

        Instant createdAt = Instant.now();
        boolean expired() { return Instant.now().isAfter(createdAt.plus(SESSION_TTL)); }
        void invalidate() { rejected = true; }
    }

    private static volatile Session current;
    private static int PORT = 8889;

    public static void main(String[] args) {
        try {
            if (System.getProperty("port") != null) {
                PORT = Integer.parseInt(System.getProperty("port"));
            }
            ensureFreshSession();
            writeQR(current);
            startHttp();
            System.out.println("\nOpen http://localhost:" + PORT + "/  (scan this QR from your phone)");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ---------- session lifecycle ----------
    private static void ensureFreshSession() throws Exception {
        if (current == null || current.expired() || current.accepted || current.rejected) {
            current = newSession();
        }
    }
    private static Session getSessionOrRotate() throws Exception {
        if (current == null || current.expired()) {
            current = newSession();
            writeQR(current);
        }
        return current;
    }
    private static Session newSession() {
        Session s = new Session();
        s.sid = base64url(RNG, 10);
        s.sdPriv = new BigInteger(2048, RNG).mod(P);
        s.sdPub  = G.modPow(s.sdPriv, P);
        s.rSD    = rand(16);
        s.cSDHex = sha256hex(join(s.rSD, s.sdPub.toString().getBytes(StandardCharsets.UTF_8)));
        System.out.println("[New session] sid=" + s.sid + " sdPub(hex32)=" + s.sdPub.toString(16).substring(0,32) + "...");
        return s;
    }
    private static void writeQR(Session s) throws Exception {
        String payload = s.sid + "|" + s.sdPub.toString() + "|" + s.cSDHex;
        BitMatrix m = new MultiFormatWriter().encode(payload, BarcodeFormat.QR_CODE, 300, 300);
        MatrixToImageWriter.writeToPath(m, "PNG", new File("sas_qr.png").toPath());
        System.out.println("QR saved to sas_qr.png");
    }

    // ---------- HTTP ----------
    private static void startHttp() throws IOException {
        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
        } catch (IOException bindEx) {
            System.err.println("Port " + PORT + " busy. Try: -Dport=8890 and update phone URL.");
            throw bindEx;
        }
        server.createContext("/", SASLinkerServer::handleIndex);
        server.createContext("/qr.png", ex -> serveFile(ex, new File("sas_qr.png"), "image/png"));
        server.createContext("/state", SASLinkerServer::handleState);

        server.createContext("/pd_init", SASLinkerServer::handlePdInit);       // body: sid|pdPub|cPDHex
        server.createContext("/pd_reveal", SASLinkerServer::handlePdReveal);   // body: sid|rPD(base64) -> returns rSD(base64)
        server.createContext("/pd_verify", SASLinkerServer::handlePdVerify);   // body: sid|proof(base64)
        server.createContext("/sd_local_check", SASLinkerServer::handleSdLocal); // body: sid|last2
        server.createContext("/confirm", SASLinkerServer::handleConfirm);      // body: sid|accept|reject

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    private static void handleIndex(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("GET")) { respond(ex, 405, ""); return; }
        respond(ex, 200, INDEX_HTML, "text/html; charset=utf-8");
    }
    private static void handleState(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("GET")) { respond(ex, 405, ""); return; }
        try {
            Session s = getSessionOrRotate();
            String status;
            if (s.expired()) status="expired";
            else if (s.rejected) status="rejected";
            else if (s.accepted) status="accepted";
            else if (s.pdProofOK) status="awaiting_local";
            else if (s.pdPub != null && s.rPD != null) status="pending_verify";
            else if (s.pdPub != null) status="pending_reveal";
            else status="idle";
            respond(ex, 200, "{\"sid\":\""+s.sid+"\",\"status\":\""+status+"\"}", "application/json");
        } catch (Exception e) { respond(ex, 500, e.toString()); }
    }

    private static void handlePdInit(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { respond(ex, 405, ""); return; }
        try {
            Session s = getSessionOrRotate();
            String[] p = read(ex).split("\\|");
            if (p.length != 3) { respond(ex, 400, "bad"); return; }
            if (!Objects.equals(p[0], s.sid) || s.expired()) { respond(ex, 410, "expired"); return; }
            if (s.pdPub != null) { respond(ex, 409, "taken"); return; } // first PD wins
            s.pdPub  = new BigInteger(p[1]);
            s.cPDHex = p[2];
            respond(ex, 200, "ok");
        } catch (Exception e) { respond(ex, 500, e.toString()); }
    }

    private static void handlePdReveal(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { respond(ex, 405, ""); return; }
        try {
            Session s = getSessionOrRotate();
            String[] p = read(ex).split("\\|"); // sid|rPDb64
            if (p.length != 2) { respond(ex, 400, "bad"); return; }
            if (!Objects.equals(p[0], s.sid) || s.expired() || s.pdPub == null) { respond(ex, 410, "expired"); return; }
            s.rPD = Base64.getDecoder().decode(p[1]);
            // verify PD commitment
            String exp = sha256hex(join(s.rPD, s.pdPub.toString().getBytes(StandardCharsets.UTF_8)));
            if (!exp.equalsIgnoreCase(s.cPDHex)) { s.invalidate(); respond(ex, 403, "commit-mismatch"); return; }
            // return RSD (base64) to PD
            respond(ex, 200, Base64.getEncoder().encodeToString(s.rSD));
        } catch (Exception e) { respond(ex, 500, e.toString()); }
    }

    private static void handlePdVerify(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { respond(ex, 405, ""); return; }
        try {
            Session s = getSessionOrRotate();
            String[] p = read(ex).split("\\|"); // sid|proofB64
            if (p.length != 2) { respond(ex, 400, "bad"); return; }
            if (!Objects.equals(p[0], s.sid) || s.expired() || s.pdPub == null || s.rPD == null) { respond(ex, 410, "expired"); return; }

            // verify SD commitment (now we know rSD)
            String expCSD = sha256hex(join(s.rSD, s.sdPub.toString().getBytes(StandardCharsets.UTF_8)));
            if (!expCSD.equalsIgnoreCase(s.cSDHex)) { s.invalidate(); respond(ex, 403, "commit-mismatch"); return; }

            // derive session key + SAS
            BigInteger shared = s.pdPub.modPow(s.sdPriv, P);
            byte[] kBytes = sha256(shared.toString().getBytes(StandardCharsets.UTF_8));
            s.hmacKey = Arrays.copyOf(kBytes, 32);
            s.sas = makeSAS(kBytes, s.rPD, s.rSD); // 6 chars

            // verify PD HMAC proof over transcript
            String transcript = s.sid + "|" + s.sdPub.toString() + "|" + s.pdPub.toString() + "|" +
                    s.cSDHex + "|" + s.cPDHex + "|" +
                    Base64.getEncoder().encodeToString(s.rSD) + "|" +
                    Base64.getEncoder().encodeToString(s.rPD) + "|" + s.sas;
            byte[] expected = hmacSHA256(s.hmacKey, transcript.getBytes(StandardCharsets.UTF_8));
            byte[] got = Base64.getDecoder().decode(p[1]);
            if (!MessageDigest.isEqual(expected, got)) { s.invalidate(); respond(ex, 403, "bad-proof"); return; }

            s.pdProofOK = true;
            respond(ex, 200, "ok");
        } catch (Exception e) { respond(ex, 500, e.toString()); }
    }

    private static void handleSdLocal(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { respond(ex, 405, ""); return; }
        try {
            Session s = getSessionOrRotate();
            String[] p = read(ex).split("\\|"); // sid|last2
            if (p.length != 2) { respond(ex, 400, "bad"); return; }
            if (!Objects.equals(p[0], s.sid) || s.expired() || s.sas == null) { respond(ex, 410, "expired"); return; }
            String last2 = s.sas.substring(s.sas.length() - 2);
            if (!last2.equalsIgnoreCase(p[1])) { s.invalidate(); respond(ex, 403, "mismatch"); return; }
            s.sdLocalOK = true;
            respond(ex, 200, "ok");
        } catch (Exception e) { respond(ex, 500, e.toString()); }
    }

    private static void handleConfirm(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { respond(ex, 405, ""); return; }
        try {
            Session s = getSessionOrRotate();
            String[] p = read(ex).split("\\|"); // sid|accept|reject
            if (p.length != 2) { respond(ex, 400, "bad"); return; }
            if (!Objects.equals(p[0], s.sid) || s.expired()) { respond(ex, 410, "expired"); return; }
            if (!s.pdProofOK || !s.sdLocalOK) { respond(ex, 409, "not-ready"); return; }
            if ("accept".equalsIgnoreCase(p[1])) { s.accepted = true; respond(ex, 200, "accepted"); }
            else if ("reject".equalsIgnoreCase(p[1])) { s.rejected = true; respond(ex, 200, "rejected"); }
            else { respond(ex, 400, "unknown"); }
        } catch (Exception e) { respond(ex, 500, e.toString()); }
    }

    // ---------- helpers ----------
    private static byte[] rand(int n){ byte[] b = new byte[n]; RNG.nextBytes(b); return b; }
    private static String base64url(SecureRandom rng, int n){ byte[] b = new byte[n]; rng.nextBytes(b); return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    private static byte[] join(byte[] a, byte[] b){ byte[] c = new byte[a.length+b.length]; System.arraycopy(a,0,c,0,a.length); System.arraycopy(b,0,c,a.length,b.length); return c; }

    private static byte[] sha256(byte[] in){
        try { return MessageDigest.getInstance("SHA-256").digest(in); }
        catch(Exception e){ throw new RuntimeException(e); }
    }
    private static String sha256hex(byte[] in){
        byte[] d = sha256(in); StringBuilder sb = new StringBuilder();
        for(byte x: d) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] hmacSHA256(byte[] key, byte[] msg){
        try{ Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key,"HmacSHA256")); return mac.doFinal(msg); }
        catch(Exception e){ throw new RuntimeException(e); }
    }

    private static String base32(byte[] data){
        final String A="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder out=new StringBuilder(); int curr=0,bits=0;
        for(byte datum: data){ curr=(curr<<8)|(datum&0xff); bits+=8; while(bits>=5){ out.append(A.charAt((curr>>(bits-5))&31)); bits-=5; } }
        if(bits>0) out.append(A.charAt((curr<<(5-bits)) & 31));
        return out.toString();
    }
    private static String makeSAS(byte[] kBytes, byte[] rPD, byte[] rSD){
        byte[] mac = hmacSHA256(Arrays.copyOf(kBytes,32), join("SAS|".getBytes(StandardCharsets.UTF_8), join(rPD, rSD)));
        String b32 = base32(mac).replace("=","");
        String six = b32.substring(0,6);
        return six.replace('2','0').replace('3','1').replace('4','2').replace('5','3').replace('6','4').replace('7','5');
    }

    private static void serveFile(HttpExchange ex, File f, String ctype) throws IOException {
        if (!f.exists()) { respond(ex, 404, "not found"); return; }
        ex.getResponseHeaders().set("Content-Type", ctype);
        ex.sendResponseHeaders(200, f.length());
        try (OutputStream os = ex.getResponseBody()) { Files.copy(f.toPath(), os); }
    }
    private static String read(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) { return new String(is.readAllBytes(), StandardCharsets.UTF_8); }
    }
    private static void respond(HttpExchange ex, int code, String body) throws IOException { respond(ex, code, body, "text/plain; charset=utf-8"); }
    private static void respond(HttpExchange ex, int code, String body, String ctype) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", ctype);
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    // ---------- minimal desktop UI ----------
    private static final String INDEX_HTML = """
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>SASLinker Desktop — Hardened</title>
<style>
:root{--bg:#111b21;--panel:#202c33;--muted:#aebac1;--primary:#25d366}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:#e9edef}
.wrap{display:flex;min-height:100vh}
.card{background:var(--panel);border-radius:16px;padding:24px;box-shadow:0 6px 24px rgba(0,0,0,.35);width:860px;max-width:92vw;margin:auto}
.grid{display:grid;grid-template-columns:320px 1fr;gap:28px;align-items:start}
.qr{width:280px;height:280px;border-radius:12px;background:#111;display:block;margin:0 auto 8px auto}
.sub{font-size:13px;color:var(--muted)}
.input{padding:10px;border-radius:10px;border:none;outline:none;width:120px}
.btn{border:0;border-radius:10px;padding:10px 14px;cursor:pointer;font-weight:700}
.btn-primary{background:var(--primary);color:#062f1a}
.btn-danger{background:#ef5350;color:#2b1110}
.hidden{display:none!important}
.center{text-align:center}
.chip{display:inline-block;padding:6px 10px;border-radius:999px;background:#0b3d2e;color:#59f1a8;font-weight:700;font-size:12px;margin-top:8px}
</style>
</head>
<body>
<div class='wrap'>
  <div class='card'>
    <div class='grid'>
      <div>
        <img class='qr' src='/qr.png' alt='QR code'>
        <div id='sid' class='sub'></div>
        <div id='phase' class='sub'>Waiting for phone to scan…</div>
      </div>
      <div>
        <h2>Secure Device Linking</h2>
        <ol>
          <li>On your phone, open SASLinker and tap <b>Scan QR</b>.</li>
          <li>Compare the SAS shown on <b>your phone</b> with what you expect.</li>
          <li>Phone sends a cryptographic proof. Then type the <b>last two</b> SAS characters here and click <b>Accept</b>.</li>
        </ol>
        <div id='awaitBlock' class='hidden'>
          <div class='chip'>Phone proof verified — final local check</div>
          <div style='margin-top:10px'>Enter last two SAS chars:
            <input id='last2' class='input' maxlength='2'/> <button class='btn' onclick='localCheck()'>Check</button>
          </div>
        </div>
        <div id='actions' class='hidden' style='margin-top:14px'>
          <button class='btn btn-primary' onclick='confirm("accept")'>Accept</button>
          <button class='btn btn-danger' onclick='confirm("reject")'>Reject</button>
        </div>
        <div id='result' class='hidden'></div>
      </div>
    </div>
  </div>
</div>
<script>
let sid=null,lastStatus='';
async function poll(){
  const r = await fetch('/state',{cache:'no-store'}); const j = await r.json();
  document.getElementById('sid').textContent = 'Session: '+j.sid;
  sid=j.sid; if(j.status===lastStatus) return; lastStatus=j.status;
  const awaitBlock=document.getElementById('awaitBlock');
  const actions=document.getElementById('actions');
  const phase=document.getElementById('phase');
  const result=document.getElementById('result');
  if(j.status==='idle'){ phase.textContent='Waiting for phone to scan…'; awaitBlock.classList.add('hidden'); actions.classList.add('hidden'); result.classList.add('hidden'); }
  if(j.status==='pending_reveal'){ phase.textContent='Phone connected — waiting for phone to reveal its nonce…'; }
  if(j.status==='pending_verify'){ phase.textContent='Phone is computing SAS…'; }
  if(j.status==='awaiting_local'){ phase.textContent='Phone proof verified.'; awaitBlock.classList.remove('hidden'); }
  if(j.status==='accepted'){ phase.textContent='Linked.'; result.classList.remove('hidden'); result.textContent='🎉 Linked successfully.'; awaitBlock.classList.add('hidden'); actions.classList.add('hidden'); }
  if(j.status==='rejected'){ phase.textContent='Rejected.'; result.classList.remove('hidden'); result.textContent='❌ Rejected.'; }
  if(j.status==='expired'){ phase.textContent='Session expired. Refresh to restart.'; }
}
async function localCheck(){
  const v=document.getElementById('last2').value.trim(); if(v.length!==2) return;
  const r=await fetch('/sd_local_check',{method:'POST',body:sid+'|'+v});
  if(r.ok){ document.getElementById('actions').classList.remove('hidden'); }
}
async function confirm(which){ const r=await fetch('/confirm',{method:'POST',body:sid+'|'+which}); if(r.ok) poll(); }
setInterval(poll,1000); poll();
</script>
</body>
</html>
""";
}
