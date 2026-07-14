package pqkerberos;

import pqkerberos.ProtocolMessages.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class KDCServer {

    protected KeyPair kdcSigningKeyPair;
    protected KeyPair kdcKEMKeyPair;

    private final Map<String, byte[]> userDatabase    = new ConcurrentHashMap<>();
    private final Map<String, byte[]> serviceDatabase = new ConcurrentHashMap<>();
    private final Set<String> replayCacheAS  = ConcurrentHashMap.newKeySet();
    private final Set<String> replayCacheTGS = ConcurrentHashMap.newKeySet();

    protected SecretKey kdcTGSKey;

    public static final int AS_PORT  = 8888;
    public static final int TGS_PORT = 8889;

    public static void main(String[] args) throws Exception {
        KDCServer kdc = new KDCServer();
        kdc.initialize();
        kdc.start();
    }

    public void initialize() throws GeneralSecurityException {
        System.out.println("[KDC] Generating PQ keypairs...");
        long t0 = System.currentTimeMillis();

        kdcSigningKeyPair = PQCrypto.generateSigningKeyPair();
        System.out.println("[KDC] Dilithium-3 signing key generated.");

        kdcKEMKeyPair = PQCrypto.generateKEMKeyPair();
        System.out.println("[KDC] Kyber-768 KEM key generated.");

        byte[] tgsKeyBytes = new byte[32];
        new SecureRandom().nextBytes(tgsKeyBytes);
        kdcTGSKey = new SecretKeySpec(tgsKeyBytes, "AES");

        System.out.printf("[KDC] Keys ready in %d ms%n", System.currentTimeMillis() - t0);

        registerUser("alice@PQKERBEROS.REALM");
        registerUser("bob@PQKERBEROS.REALM");
        System.out.println("[KDC] Registered users: alice, bob");

        registerService("fileservice@PQKERBEROS.REALM");
        System.out.println("[KDC] Registered service: fileservice");
    }

    private void registerUser(String clientId) {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        userDatabase.put(clientId, key);
    }

    private void registerService(String serviceName) {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        serviceDatabase.put(serviceName, key);
    }

    protected void start() throws IOException {
        ExecutorService asPool  = Executors.newCachedThreadPool();
        ExecutorService tgsPool = Executors.newCachedThreadPool();

        new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(AS_PORT)) {
                System.out.println("[AS]  Listening on port " + AS_PORT);
                while (true) { Socket c = ss.accept(); asPool.submit(() -> handleASRequest(c)); }
            } catch (IOException e) { System.err.println("[AS] Error: " + e.getMessage()); }
        }).start();

        new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(TGS_PORT)) {
                System.out.println("[TGS] Listening on port " + TGS_PORT);
                while (true) { Socket c = ss.accept(); tgsPool.submit(() -> handleTGSRequest(c)); }
            } catch (IOException e) { System.err.println("[TGS] Error: " + e.getMessage()); }
        }).start();

        System.out.println("[KDC] Ready.\n");
    }

    private void handleASRequest(Socket clientSocket) {
        try {
            ASRequest request = MessageIO.receive(clientSocket, ASRequest.class);
            System.out.println("[AS]  Request from: " + request.clientId);

            if (request.isExpired()) { sendError(clientSocket, "Request expired"); return; }
            if (!userDatabase.containsKey(request.clientId)) { sendError(clientSocket, "Unknown client"); return; }

            String replayKey = request.clientId + ":" + request.timestamp + ":" + Arrays.toString(request.nonce);
            if (!replayCacheAS.add(replayKey)) { sendError(clientSocket, "Replay detected"); return; }

            ASResponse response = buildASResponse(request);
            MessageIO.send(clientSocket, response);
            System.out.println("[AS]  TGT issued to: " + request.clientId);

        } catch (Exception e) {
            System.err.println("[AS]  Error: " + e.getMessage());
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    private ASResponse buildASResponse(ASRequest request) throws Exception {
        ASResponse response = new ASResponse();
        response.nonce = request.nonce;

        byte[] sessionKeyBytes = new byte[32];
        new SecureRandom().nextBytes(sessionKeyBytes);
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        TicketInner tgtInner = new TicketInner(
                request.clientId, sessionKeyBytes, response.timestamp, response.expiryTimestamp);
        byte[] tgtEncrypted = PQCrypto.encrypt(MessageIO.toBytes(tgtInner), kdcTGSKey);
        response.tgt = new EncryptedTicket(tgtEncrypted, "krbtgt");

        PublicKey clientKEMKey = deserializeKEMPublicKey(request.clientKEMPublicKey);
        PQCrypto.KEMResult kemResult = PQCrypto.encapsulate(clientKEMKey);
        response.kyberCiphertext = kemResult.ciphertext;

        SecretKey kemDerivedKey = PQCrypto.deriveAESKey(kemResult.sharedSecret, "as-session-key-wrap".getBytes());
        response.encryptedSessionKey = PQCrypto.encrypt(sessionKeyBytes, kemDerivedKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.write(response.tgt.encryptedData);
        dos.write(response.kyberCiphertext);
        dos.writeLong(response.timestamp);
        dos.writeLong(response.expiryTimestamp);
        dos.write(response.nonce);
        dos.flush();
        response.signedData  = baos.toByteArray();
        response.kdcSignature = PQCrypto.sign(response.signedData, kdcSigningKeyPair.getPrivate());

        return response;
    }

    private void handleTGSRequest(Socket clientSocket) {
        try {
            TGSRequest request = MessageIO.receive(clientSocket, TGSRequest.class);
            System.out.println("[TGS] Service requested: " + request.serviceName);

            TicketInner tgtContents = decryptTicket(request.tgt, kdcTGSKey);
            if (tgtContents == null || tgtContents.isExpired()) { sendError(clientSocket, "TGT invalid"); return; }

            SecretKey sessionKey = new SecretKeySpec(tgtContents.sessionKey, "AES");
            AuthenticatorInner auth = decryptAuthenticator(request.authenticator, sessionKey);
            if (auth == null || auth.isExpired()) { sendError(clientSocket, "Authenticator invalid"); return; }
            if (!auth.clientId.equals(tgtContents.clientId)) { sendError(clientSocket, "Identity mismatch"); return; }

            String replayKey = auth.clientId + ":" + auth.timestamp + ":" + auth.sequenceNumber;
            if (!replayCacheTGS.add(replayKey)) { sendError(clientSocket, "Replay detected"); return; }

            if (!serviceDatabase.containsKey(request.serviceName)) { sendError(clientSocket, "Unknown service"); return; }

            TGSResponse response = buildTGSResponse(request, tgtContents);
            MessageIO.send(clientSocket, response);
            System.out.println("[TGS] Service ticket: " + tgtContents.clientId + " → " + request.serviceName);

        } catch (Exception e) {
            System.err.println("[TGS] Error: " + e.getMessage());
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    private TGSResponse buildTGSResponse(TGSRequest request, TicketInner tgtContents) throws Exception {
        TGSResponse response = new TGSResponse();

        byte[] serviceSessionKeyBytes = new byte[32];
        new SecureRandom().nextBytes(serviceSessionKeyBytes);

        byte[] serviceKey = serviceDatabase.get(request.serviceName);
        SecretKey serviceSecretKey = new SecretKeySpec(serviceKey, "AES");

        TicketInner inner = new TicketInner(
                tgtContents.clientId, serviceSessionKeyBytes, response.timestamp, response.expiryTimestamp);
        byte[] ticketEncrypted = PQCrypto.encrypt(MessageIO.toBytes(inner), serviceSecretKey);
        response.serviceTicket = new EncryptedTicket(ticketEncrypted, request.serviceName);

        PublicKey clientKEMKey = deserializeKEMPublicKey(request.clientServiceKEMPublicKey);
        PQCrypto.KEMResult kemResult = PQCrypto.encapsulate(clientKEMKey);
        response.kyberCiphertext = kemResult.ciphertext;

        SecretKey kemDerivedKey = PQCrypto.deriveAESKey(kemResult.sharedSecret, "tgs-service-session-key-wrap".getBytes());
        response.encryptedServiceSessionKey = PQCrypto.encrypt(serviceSessionKeyBytes, kemDerivedKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.write(response.serviceTicket.encryptedData);
        dos.write(response.kyberCiphertext);
        dos.writeLong(response.timestamp);
        dos.flush();
        response.signedData   = baos.toByteArray();
        response.kdcSignature = PQCrypto.sign(response.signedData, kdcSigningKeyPair.getPrivate());

        return response;
    }

    public PublicKey getSigningPublicKey() { return kdcSigningKeyPair.getPublic(); }

    public byte[] getServiceKeyForDemo(String serviceName) {
    return serviceDatabase.computeIfAbsent(serviceName, name -> {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    });
}

    private TicketInner decryptTicket(EncryptedTicket ticket, SecretKey key) {
        try {
            return MessageIO.fromBytes(PQCrypto.decrypt(ticket.encryptedData, key), TicketInner.class);
        } catch (Exception e) { return null; }
    }

    private AuthenticatorInner decryptAuthenticator(EncryptedAuthenticator auth, SecretKey key) {
        try {
            return MessageIO.fromBytes(PQCrypto.decrypt(auth.encryptedData, key), AuthenticatorInner.class);
        } catch (Exception e) { return null; }
    }

    private PublicKey deserializeKEMPublicKey(byte[] keyBytes) throws Exception {
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(PQCrypto.KEM_ALGORITHM, PQCrypto.PROVIDER_PQC).generatePublic(keySpec);
    }

    private void sendError(Socket socket, String message) {
        try { MessageIO.send(socket, new ErrorMessage(message)); } catch (IOException ignored) {}
    }
}