package pqkerberos;

import java.io.Serializable;
import java.time.Instant;

public class ProtocolMessages {

    // ── Step 1: Client → KDC AS ──────────────────────────────
    public static class ASRequest implements Serializable {
        public String clientId;
        public byte[] clientKEMPublicKey;
        public byte[] nonce;
        public long   timestamp;
        public String requestedService;

        public ASRequest(String clientId, byte[] kemPublicKey) {
            this.clientId           = clientId;
            this.clientKEMPublicKey = kemPublicKey;
            this.nonce              = new byte[32];
            new java.security.SecureRandom().nextBytes(this.nonce);
            this.timestamp          = Instant.now().toEpochMilli();
            this.requestedService   = "krbtgt";
        }

        public boolean isExpired() {
            return (Instant.now().toEpochMilli() - timestamp) / 1000 > 300;
        }
    }

    // ── Step 2: KDC AS → Client ──────────────────────────────
    public static class ASResponse implements Serializable {
        public EncryptedTicket tgt;
        public byte[] kyberCiphertext;
        public byte[] encryptedSessionKey;
        public byte[] nonce;
        public long   timestamp;
        public long   expiryTimestamp;
        public byte[] kdcSignature;
        public byte[] signedData;

        public ASResponse() {
            this.timestamp       = Instant.now().toEpochMilli();
            this.expiryTimestamp = this.timestamp + (8 * 3600 * 1000L);
        }
    }

    // ── Step 3: Client → KDC TGS ─────────────────────────────
    public static class TGSRequest implements Serializable {
        public EncryptedTicket        tgt;
        public String                 serviceName;
        public EncryptedAuthenticator authenticator;
        public byte[]                 clientServiceKEMPublicKey;

        public TGSRequest(EncryptedTicket tgt, String serviceName,
                          EncryptedAuthenticator authenticator, byte[] kemPublicKey) {
            this.tgt                      = tgt;
            this.serviceName              = serviceName;
            this.authenticator            = authenticator;
            this.clientServiceKEMPublicKey = kemPublicKey;
        }
    }

    // ── Step 4: KDC TGS → Client ─────────────────────────────
    public static class TGSResponse implements Serializable {
        public EncryptedTicket serviceTicket;
        public byte[] kyberCiphertext;
        public byte[] encryptedServiceSessionKey;
        public long   timestamp;
        public long   expiryTimestamp;
        public byte[] kdcSignature;
        public byte[] signedData;

        public TGSResponse() {
            this.timestamp       = Instant.now().toEpochMilli();
            this.expiryTimestamp = this.timestamp + (3600 * 1000L);
        }
    }

    // ── Step 5: Client → Service ──────────────────────────────
    public static class APRequest implements Serializable {
        public EncryptedTicket        serviceTicket;
        public EncryptedAuthenticator authenticator;
        public boolean                requestMutualAuth;
        public byte[]                 requestPayload;

        public APRequest(EncryptedTicket ticket, EncryptedAuthenticator auth) {
            this.serviceTicket    = ticket;
            this.authenticator    = auth;
            this.requestMutualAuth = true;
        }
    }

    // ── Step 6: Service → Client ──────────────────────────────
    public static class APResponse implements Serializable {
        public byte[]  encryptedClientTimestampPlusOne;
        public byte[]  responsePayload;
        public boolean success;
        public String  message;

        public APResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    // ── Supporting structures ─────────────────────────────────

    public static class EncryptedTicket implements Serializable {
        public byte[] encryptedData;
        public byte[] kdcSignature;
        public String targetService;
        public long   issueTimestamp;

        public EncryptedTicket(byte[] encryptedData, String targetService) {
            this.encryptedData  = encryptedData;
            this.targetService  = targetService;
            this.issueTimestamp = Instant.now().toEpochMilli();
        }
    }

    public static class TicketInner implements Serializable {
        public String clientId;
        public byte[] sessionKey;
        public long   issueTimestamp;
        public long   expiryTimestamp;

        public TicketInner(String clientId, byte[] sessionKey,
                           long issueTimestamp, long expiryTimestamp) {
            this.clientId       = clientId;
            this.sessionKey     = sessionKey;
            this.issueTimestamp = issueTimestamp;
            this.expiryTimestamp = expiryTimestamp;
        }

        public boolean isExpired() {
            return Instant.now().toEpochMilli() > expiryTimestamp;
        }
    }

    public static class EncryptedAuthenticator implements Serializable {
        public byte[] encryptedData;
        public EncryptedAuthenticator(byte[] encryptedData) {
            this.encryptedData = encryptedData;
        }
    }

    public static class AuthenticatorInner implements Serializable {
        public String clientId;
        public long   timestamp;
        public int    sequenceNumber;

        public AuthenticatorInner(String clientId) {
            this.clientId       = clientId;
            this.timestamp      = Instant.now().toEpochMilli();
            this.sequenceNumber = new java.security.SecureRandom().nextInt();
        }

        public boolean isExpired() {
            return (Instant.now().toEpochMilli() - timestamp) / 1000 > 300;
        }
    }

    public static class ErrorMessage implements Serializable {
        public final String reason;
        public ErrorMessage(String reason) { this.reason = reason; }
    }
}