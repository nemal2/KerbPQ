package pqkerberos;

import pqkerberos.ProtocolMessages.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.Socket;
import java.security.*;

public class PQKerberosClient {

    private final String    clientId;
    private final String    kdcHost;
    private final PublicKey kdcSigningKey;

    private KeyPair        kemKeyPairForAS;
    private KeyPair        kemKeyPairForService;
    private EncryptedTicket tgt;
    private SecretKey      tgsSessionKey;
    private EncryptedTicket serviceTicket;
    private SecretKey      serviceSessionKey;

    public PQKerberosClient(String clientId, String kdcHost, PublicKey kdcSigningKey) {
        this.clientId     = clientId;
        this.kdcHost      = kdcHost;
        this.kdcSigningKey = kdcSigningKey;
    }

    public APResponse authenticateAndAccess(String serviceName, String serviceHost,
                                            int servicePort, byte[] requestPayload) throws Exception {
        System.out.println("\n[Client] === PQ-Kerberos authentication ===");
        System.out.println("[Client] Identity: " + clientId);
        System.out.println("[Client] Target:   " + serviceName);

        obtainTGT();
        obtainServiceTicket(serviceName);
        return accessService(serviceHost, servicePort, serviceName, requestPayload);
    }

    private void obtainTGT() throws Exception {
        System.out.println("\n[Client] --- Step 1+2: AS Exchange ---");

        kemKeyPairForAS = PQCrypto.generateKEMKeyPair();
        System.out.println("[Client] Kyber-768 keypair generated.");

        ASRequest request = new ASRequest(clientId, kemKeyPairForAS.getPublic().getEncoded());

        ASResponse response;
        try (Socket socket = new Socket(kdcHost, KDCServer.AS_PORT)) {
            System.out.println("[Client] Connected to KDC AS port " + KDCServer.AS_PORT);
            MessageIO.send(socket, request);
            Object reply = MessageIO.receive(socket, Object.class);

            if (reply instanceof ErrorMessage) {
                throw new SecurityException("KDC AS error: " + ((ErrorMessage) reply).reason);
            }
            response = (ASResponse) reply;
        }

        if (!PQCrypto.verify(response.signedData, response.kdcSignature, kdcSigningKey)) {
            throw new SecurityException("KDC signature INVALID — possible MITM!");
        }
        System.out.println("[Client] KDC Dilithium-3 signature verified ✓");

        byte[] sharedSecret = PQCrypto.decapsulate(kemKeyPairForAS.getPrivate(), response.kyberCiphertext);
        System.out.println("[Client] Kyber-768 decapsulation successful ✓");

        SecretKey kemDerivedKey = PQCrypto.deriveAESKey(sharedSecret, "as-session-key-wrap".getBytes());
        byte[] sessionKeyBytes = PQCrypto.decrypt(response.encryptedSessionKey, kemDerivedKey);
        tgsSessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        tgt = response.tgt;
        System.out.println("[Client] TGT obtained. Valid until: " + new java.util.Date(response.expiryTimestamp));
    }

    private void obtainServiceTicket(String serviceName) throws Exception {
        System.out.println("\n[Client] --- Step 3+4: TGS Exchange ---");

        kemKeyPairForService = PQCrypto.generateKEMKeyPair();
        EncryptedAuthenticator authenticator = buildAuthenticator(tgsSessionKey);

        TGSRequest request = new TGSRequest(
                tgt, serviceName, authenticator, kemKeyPairForService.getPublic().getEncoded());

        TGSResponse response;
        try (Socket socket = new Socket(kdcHost, KDCServer.TGS_PORT)) {
            System.out.println("[Client] Connected to KDC TGS port " + KDCServer.TGS_PORT);
            MessageIO.send(socket, request);
            Object reply = MessageIO.receive(socket, Object.class);

            if (reply instanceof ErrorMessage) {
                throw new SecurityException("KDC TGS error: " + ((ErrorMessage) reply).reason);
            }
            response = (TGSResponse) reply;
        }

        if (!PQCrypto.verify(response.signedData, response.kdcSignature, kdcSigningKey)) {
            throw new SecurityException("TGS response signature INVALID!");
        }
        System.out.println("[Client] TGS signature verified ✓");

        byte[] sharedSecret = PQCrypto.decapsulate(kemKeyPairForService.getPrivate(), response.kyberCiphertext);
        SecretKey kemDerivedKey = PQCrypto.deriveAESKey(sharedSecret, "tgs-service-session-key-wrap".getBytes());
        byte[] svcKeyBytes = PQCrypto.decrypt(response.encryptedServiceSessionKey, kemDerivedKey);
        serviceSessionKey = new SecretKeySpec(svcKeyBytes, "AES");

        serviceTicket = response.serviceTicket;
        System.out.println("[Client] Service ticket obtained. Valid until: " + new java.util.Date(response.expiryTimestamp));
    }

    private APResponse accessService(String serviceHost, int servicePort,
                                     String serviceName, byte[] payload) throws Exception {
        System.out.println("\n[Client] --- Step 5+6: AP Exchange ---");

        EncryptedAuthenticator authenticator = buildAuthenticator(serviceSessionKey);
        APRequest apRequest = new APRequest(serviceTicket, authenticator);
        apRequest.requestPayload   = payload;
        apRequest.requestMutualAuth = true;

        APResponse response;
        try (Socket socket = new Socket(serviceHost, servicePort)) {
            System.out.println("[Client] Connected to service on port " + servicePort);
            MessageIO.send(socket, apRequest);
            response = MessageIO.receive(socket, APResponse.class);
        }

        if (response.encryptedClientTimestampPlusOne != null) {
            System.out.println("[Client] Mutual authentication verified ✓");
        }
        System.out.println("[Client] Service says: " + response.message);
        return response;
    }

    private EncryptedAuthenticator buildAuthenticator(SecretKey sessionKey) throws Exception {
        AuthenticatorInner inner = new AuthenticatorInner(clientId);
        byte[] encrypted = PQCrypto.encrypt(MessageIO.toBytes(inner), sessionKey);
        return new EncryptedAuthenticator(encrypted);
    }
}