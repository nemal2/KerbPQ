package pqkerberos;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class FileService {

    private final String serviceName;
    private final int port;

    public FileService(String serviceName, int port) {
        this.serviceName = serviceName;
        this.port = port;
    }

    public void start() throws IOException {
        System.out.println("[Service] " + serviceName + " starting on port " + port);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket client = serverSocket.accept();
                handleRequest(client);
            }
        }
    }

    private void handleRequest(Socket clientSocket) {
        System.out.println("[Service] Connection received");
    }
}