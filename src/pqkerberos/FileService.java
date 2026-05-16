package pqkerberos;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import pqkerberos.MessageIO.*;
import pqkerberos.ProtocolMessages.*;


public class FileService {

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

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}