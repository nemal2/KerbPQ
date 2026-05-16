package pqkerberos;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;


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

    private void handleRequest(Socket clientSocket) {
        String clientAddr = clientSocket.getRemoteSocketAddress().toString();
        System.out.println("[Service] Connection from " + clientAddr);
    }
}