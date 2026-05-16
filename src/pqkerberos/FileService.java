package pqkerberos;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FileService {

    private final String serviceName;
    private final int port;

    public FileService(String serviceName, int port) {
        this.serviceName = serviceName;
        this.port = port;
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
        System.out.println("[Service] Connection received");
    }
}