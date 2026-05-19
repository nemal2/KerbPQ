package pqkerberos;

import pqkerberos.*;
import pqkerberos.MessageIO.*;
import pqkerberos.ProtocolMessages.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.*;
import java.security.*;
import java.util.Set;
import java.util.concurrent.*;

public class FileService {

    private final String serviceName;
    private final int port;
    private final SecretKey longTermKey;         // Pre-shared with KDC
    private final PublicKey kdcSigningPublicKey; // To verify ticket signatures

    // Replay cache: reject authenticators we've seen before
    private final Set<String> replayCache = ConcurrentHashMap.newKeySet();

    public FileService(String serviceName, int port,
                       byte[] longTermKeyBytes, PublicKey kdcSigningKey) {
        this.serviceName = serviceName;
        this.port = port;
        this.longTermKey = new SecretKeySpec(longTermKeyBytes, "AES");
        this.kdcSigningPublicKey = kdcSigningKey;
    }

    public void start() throws IOException {
        System.out.println("[Service] " + serviceName + " starting on port " + port);
        ExecutorService pool = Executors.newCachedThreadPool();

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("[Service] Ready to accept authenticated requests.");
            while (true) {
                Socket client = serverSocket.accept();
                pool.submit(() -> handleRequest(client));
            }
        }
    }

    private void handleRequest(Socket clientSocket) {
        String clientAddr = clientSocket.getRemoteSocketAddress().toString();
        System.out.println("\n[Service] Connection from " + clientAddr);

        try {
            APRequest request = MessageIO.receive(clientSocket, APRequest.class);

            // Step A: Verify the service ticket is intended for us
            EncryptedTicket ticket = request.serviceTicket;
            if (!serviceName.equals(ticket.targetService)) {
                System.out.println("[Service] REJECTED: Ticket for wrong service: " + ticket.targetService);
                sendResponse(clientSocket, new APResponse(false, "Wrong service"));
                return;
            }

            // Step B: Decrypt the service ticket using our long-term key
            // Only we and the KDC know this key — if decryption succeeds, ticket is genuine
            TicketInner ticketContents;
            try {
                byte[] plaintext = PQCrypto.decrypt(ticket.encryptedData, longTermKey);
                ticketContents = MessageIO.fromBytes(plaintext, TicketInner.class);
            } catch (Exception e) {
                System.out.println("[Service] REJECTED: Ticket decryption failed (tampered or wrong key)");
                sendResponse(clientSocket, new APResponse(false, "Invalid ticket"));
                return;
            }

            // Step C: Check ticket hasn't expired
            if (ticketContents.isExpired()) {
                System.out.println("[Service] REJECTED: Expired ticket for " + ticketContents.clientId);
                sendResponse(clientSocket, new APResponse(false, "Ticket expired"));
                return;
            }

            // Step D: Decrypt the authenticator using the session key from the ticket
            // This proves the client has the session key (i.e., the KDC verified their identity)
            SecretKey sessionKey = new SecretKeySpec(ticketContents.sessionKey, "AES");
            AuthenticatorInner auth;
            try {
                byte[] authPlaintext = PQCrypto.decrypt(request.authenticator.encryptedData, sessionKey);
                auth = MessageIO.fromBytes(authPlaintext, AuthenticatorInner.class);
            } catch (Exception e) {
                System.out.println("[Service] REJECTED: Authenticator decryption failed");
                sendResponse(clientSocket, new APResponse(false, "Invalid authenticator"));
                return;
            }

            // Step E: Check authenticator freshness
            if (auth.isExpired()) {
                System.out.println("[Service] REJECTED: Stale authenticator from " + auth.clientId);
                sendResponse(clientSocket, new APResponse(false, "Authenticator expired"));
                return;
            }

            // Step F: Replay detection — same authenticator cannot be used twice
            String replayKey = auth.clientId + ":" + auth.timestamp + ":" + auth.sequenceNumber;
            if (!replayCache.add(replayKey)) {
                System.out.println("[Service] REJECTED: Replay attack detected from " + auth.clientId);
                sendResponse(clientSocket, new APResponse(false, "Replay detected"));
                return;
            }

            // Step G: Verify clientId in authenticator matches clientId in ticket
            if (!auth.clientId.equals(ticketContents.clientId)) {
                System.out.println("[Service] REJECTED: Authenticator/ticket clientId mismatch");
                sendResponse(clientSocket, new APResponse(false, "Identity mismatch"));
                return;
            }

            // All checks passed! Client is authenticated.
            System.out.println("[Service] ✓ Client authenticated: " + ticketContents.clientId);

            // Process the actual request
            String result = processRequest(ticketContents.clientId, request.requestPayload);

            // Step H: Mutual authentication response
            // Encrypt auth.timestamp + 1 with session key to prove we decrypted the ticket
            APResponse response = new APResponse(true,
                    "Request processed for " + ticketContents.clientId + ": " + result);
            if (request.requestMutualAuth) {
                byte[] timestampPlusOne = longToBytes(auth.timestamp + 1);
                response.encryptedClientTimestampPlusOne = PQCrypto.encrypt(timestampPlusOne, sessionKey);
            }
            response.responsePayload = result.getBytes();

            sendResponse(clientSocket, response);

        } catch (Exception e) {
            System.err.println("[Service] Error handling request: " + e.getMessage());
            e.printStackTrace();
            try { sendResponse(clientSocket, new APResponse(false, "Server error")); }
            catch (Exception ignored) {}
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    private String processRequest(String clientId, byte[] payload) {
        // Simulate file service logic
        String request = payload != null ? new String(payload) : "(no payload)";
        System.out.println("[Service] Processing: '" + request + "' for user " + clientId);

        // In a real service: authorize the action, access the file system, etc.
        if (request.startsWith("READ")) {
            return "FILE_CONTENT: {simulated content for " + request + "}";
        } else if (request.startsWith("LIST")) {
            return "FILES: [document.pdf, report.docx, data.csv]";
        } else {
            return "ECHO: " + request;
        }
    }

    private void sendResponse(Socket socket, APResponse response) throws Exception {
        MessageIO.send(socket, response);
    }

    private static byte[] longToBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println("[Demo] Run Demo.java for the integrated demonstration.");
    }
}