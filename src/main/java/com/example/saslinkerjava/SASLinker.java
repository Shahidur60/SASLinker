package com.example.saslinkerjava;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.Executors;
import javax.swing.*;

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

    private static String expectedSAS;
    private static boolean verified = false;
    private static volatile boolean confirmed = false; // NEW: shared with poll

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

        System.out.println("\n📢 Public Key: " + publicKey.toString(16).substring(0, 32) + "...");
        System.out.println("📢 Random Nonce: " + randomNonce);
    }

    private static void generateQRCode() throws Exception {
        String data = publicKey.toString() + ":" + randomNonce;
        BitMatrix matrix = new QRCodeWriter().encode(data, BarcodeFormat.QR_CODE, 300, 300);
        File file = new File("sas_qr.png");
        MatrixToImageWriter.writeToPath(matrix, "PNG", file.toPath());
        System.out.println("\n📷 QR code saved to sas_qr.png. Scan this with your mobile device.");
    }

    private static void startHttpServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8889), 0);

        server.createContext("/start", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try (InputStream is = exchange.getRequestBody()) {
                    String body = readRequestBody(is);
                    String[] parts = body.split(":");
                    if (parts.length != 2) {
                        respond(exchange, "Invalid input format.");
                        return;
                    }

                    BigInteger clientPub = new BigInteger(parts[0]);
                    String clientNonce = parts[1];

                    BigInteger sharedSecret = clientPub.modPow(privateKey, P);
                    expectedSAS = computeSAS(sharedSecret.toString(), randomNonce, clientNonce);
                    verified = false;
                    confirmed = false; // Reset confirmation state for new session

                    System.out.println("\n✅ SAS generated: " + expectedSAS);
                    respond(exchange, expectedSAS);
                } catch (Exception e) {
                    respond(exchange, "Error processing request: " + e.getMessage());
                }
            }
        });

        server.createContext("/verify", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try (InputStream is = exchange.getRequestBody()) {
                    String enteredSAS = readRequestBody(is);
                    System.out.println("\n🔐 SAS entered: " + enteredSAS);

                    if (expectedSAS != null && expectedSAS.equals(enteredSAS)) {
                        verified = true;
                        respond(exchange, "✅ SAS Matched. Awaiting confirmation...");
                        showConfirmationDialog();
                    } else {
                        respond(exchange, "❌ SAS Mismatch. Authentication failed.");
                    }
                } catch (Exception e) {
                    respond(exchange, "Error verifying SAS: " + e.getMessage());
                }
            }
        });

        server.createContext("/poll", exchange -> {
            if ("GET".equals(exchange.getRequestMethod())) {
                if (confirmed) {
                    respond(exchange, "accepted");
                } else {
                    respond(exchange, "waiting");
                }
            }
        });

        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        System.out.println("\n🚀 HTTP server started on port 8889. Waiting for mobile input...");
    }

    private static void showConfirmationDialog() {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Authentication Confirmation");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            JPanel panel = new JPanel();
            panel.add(new JLabel("Do you want to accept the authentication?"));

            JButton acceptButton = new JButton("Accept ✅");
            JButton rejectButton = new JButton("Reject ❌");

            acceptButton.addActionListener(e -> {
                JOptionPane.showMessageDialog(frame, "✅ Authentication Successful! Welcome 🎉");
                confirmed = true;
                frame.dispose();
            });

            rejectButton.addActionListener(e -> {
                JOptionPane.showMessageDialog(frame, "❌ Authentication Rejected.");
                confirmed = false;
                frame.dispose();
            });

            panel.add(acceptButton);
            panel.add(rejectButton);

            frame.getContentPane().add(panel);
            frame.pack();
            frame.setLocationRelativeTo(null); // Center on screen
            frame.setVisible(true);
        });
    }

    private static String readRequestBody(InputStream is) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder body = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            body.append(line);
        }
        return body.toString();
    }

    private static String computeSAS(String sharedSecret, String nonceA, String nonceB) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String combined = sharedSecret + nonceA + nonceB;
        byte[] hash = digest.digest(combined.getBytes());
        String base64 = Base64.getEncoder().encodeToString(hash);
        return base64.replaceAll("[^A-Za-z0-9]", "").substring(0, 6); // 6-character SAS
    }

    private static void respond(HttpExchange exchange, String response) throws IOException {
        byte[] responseBytes = response.getBytes();
        exchange.sendResponseHeaders(200, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
}
