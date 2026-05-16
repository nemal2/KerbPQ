package pqkerberos;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import pqkerberos.MessageIO.*;
import pqkerberos.ProtocolMessages.*;

public class FileService {

    private final Set<String> replayCache =
            ConcurrentHashMap.newKeySet();

    private final String serviceName;
    private final int port;
    private final SecretKey longTermKey;
    private final PublicKey kdcSigningPublicKey;

    public FileService(String serviceName, int port,
                       byte[] longTermKeyBytes,
                       PublicKey kdcSigningKey) {

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

    private void sendResponse(Socket socket, APResponse response) throws Exception {
        MessageIO.send(socket, response);
    }

    private void handleRequest(Socket clientSocket) {

        try {
            APRequest request = MessageIO.receive(clientSocket, APRequest.class);

            EncryptedTicket ticket = request.serviceTicket;

            if (!serviceName.equals(ticket.targetService)) {

                System.out.println("[Service] REJECTED: Wrong service ticket");

                sendResponse(clientSocket,
                        new APResponse(false, "Wrong service"));

                return;
            }

            TicketInner ticketContents;

            try {

                byte[] plaintext =
                        PQCrypto.decrypt(ticket.encryptedData, longTermKey);

                ticketContents =
                        MessageIO.fromBytes(plaintext, TicketInner.class);

            } catch (Exception e) {

                System.out.println("[Service] REJECTED: Invalid ticket");

                sendResponse(clientSocket,
                        new APResponse(false, "Invalid ticket"));

                return;
            }

            if (ticketContents.isExpired()) {

                System.out.println("[Service] REJECTED: Expired ticket");

                sendResponse(clientSocket,
                        new APResponse(false, "Ticket expired"));

                return;
            }

            SecretKey sessionKey =
                    new SecretKeySpec(ticketContents.sessionKey, "AES");

            AuthenticatorInner auth;

            try {

                byte[] authPlaintext =
                        PQCrypto.decrypt(
                                request.authenticator.encryptedData,
                                sessionKey
                        );

                auth = MessageIO.fromBytes(
                        authPlaintext,
                        AuthenticatorInner.class
                );

            } catch (Exception e) {

                System.out.println("[Service] REJECTED: Invalid authenticator");

                sendResponse(clientSocket,
                        new APResponse(false, "Invalid authenticator"));

                return;
            }

            if (auth.isExpired()) {

                System.out.println("[Service] REJECTED: Authenticator expired");

                sendResponse(clientSocket,
                        new APResponse(false, "Authenticator expired"));

                return;
            }

            // ---------------- Replay protection ----------------

            String replayKey =
                    auth.clientId + ":" +
                            auth.timestamp + ":" +
                            auth.sequenceNumber;

            if (!replayCache.add(replayKey)) {

                System.out.println("[Service] REJECTED: Replay detected");

                sendResponse(clientSocket,
                        new APResponse(false, "Replay detected"));

                return;
            }

            // ---------------- Identity check ----------------

            if (!auth.clientId.equals(ticketContents.clientId)) {

                System.out.println("[Service] REJECTED: Identity mismatch");

                sendResponse(clientSocket,
                        new APResponse(false, "Identity mismatch"));

                return;
            }

            System.out.println("[Service] ✓ Client authenticated: "
                    + ticketContents.clientId);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}