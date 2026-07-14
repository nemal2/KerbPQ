package pqkerberos;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;


import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class PQCrypto {

    public static final String KEM_ALGORITHM = "Kyber768";
    public static final String SIG_ALGORITHM = "Dilithium3";
    public static final String SYM_ALGORITHM = "AES/GCM/NoPadding";
    public static final String PROVIDER_PQC  = "BCPQC";
    public static final String PROVIDER_BC   = "BC";
    public static final int    GCM_IV_BYTES  = 12;
    public static final int    GCM_TAG_BITS  = 128;

    static {
        if (Security.getProvider("BC")    == null) Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) Security.addProvider(new BouncyCastlePQCProvider());
    }

    // ---------- ML-KEM (Kyber-768) ----------

    // ---------- ML-KEM (Kyber-768) ----------

    public static KeyPair generateKEMKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEM_ALGORITHM, PROVIDER_PQC);
        kpg.initialize(KyberParameterSpec.kyber768, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static KEMResult encapsulate(PublicKey recipientPublicKey) throws GeneralSecurityException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER_PQC);
            keyGen.init(new KEMGenerateSpec(recipientPublicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation result =
                    (SecretKeyWithEncapsulation) keyGen.generateKey();
            return new KEMResult(result.getEncoded(), result.getEncapsulation());
        } catch (Exception e) {
            throw new GeneralSecurityException("Encapsulation failed: " + e.getMessage(), e);
        }
    }

    public static byte[] decapsulate(PrivateKey privateKey, byte[] ciphertext) throws GeneralSecurityException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEM_ALGORITHM, PROVIDER_PQC);
            keyGen.init(new KEMExtractSpec(privateKey, ciphertext, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation result =
                    (SecretKeyWithEncapsulation) keyGen.generateKey();
            return result.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("Decapsulation failed: " + e.getMessage(), e);
        }
    }

    // ---------- ML-DSA (Dilithium-3) ----------

    public static KeyPair generateSigningKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(SIG_ALGORITHM, PROVIDER_PQC);
        kpg.initialize(DilithiumParameterSpec.dilithium3, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public static byte[] sign(byte[] data, PrivateKey signingKey) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(SIG_ALGORITHM, PROVIDER_PQC);
        sig.initSign(signingKey, new SecureRandom());
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey verifyKey) {
        try {
            Signature sig = Signature.getInstance(SIG_ALGORITHM, PROVIDER_PQC);
            sig.initVerify(verifyKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // ---------- AES-256-GCM ----------

    public static SecretKey deriveAESKey(byte[] sharedSecret, byte[] context) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(sharedSecret, "HmacSHA256"));
        hmac.update(context);
        hmac.update((byte) 0x01);
        return new SecretKeySpec(Arrays.copyOf(hmac.doFinal(), 32), "AES");
    }

    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(SYM_ALGORITHM, PROVIDER_BC);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plaintext);
        byte[] out = new byte[GCM_IV_BYTES + ct.length];
        System.arraycopy(iv, 0, out, 0, GCM_IV_BYTES);
        System.arraycopy(ct, 0, out, GCM_IV_BYTES, ct.length);
        return out;
    }

    public static byte[] decrypt(byte[] ivAndCt, SecretKey key) throws GeneralSecurityException {
        byte[] iv = Arrays.copyOf(ivAndCt, GCM_IV_BYTES);
        byte[] ct = Arrays.copyOfRange(ivAndCt, GCM_IV_BYTES, ivAndCt.length);
        Cipher cipher = Cipher.getInstance(SYM_ALGORITHM, PROVIDER_BC);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ct);
    }

    public static String keyToBase64(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // ---------- Inner type ----------

    public static class KEMResult {
        public final byte[] sharedSecret;
        public final byte[] ciphertext;
        public KEMResult(byte[] sharedSecret, byte[] ciphertext) {
            this.sharedSecret = sharedSecret;
            this.ciphertext   = ciphertext;
        }
    }
}