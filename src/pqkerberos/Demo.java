package pqkerberos;

import pqkerberos.ProtocolMessages.*;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Demo.java — Enhanced with clearer output and an optional attack demonstration mode.
 *
 * Run modes:
 *   java pqkerberos.Demo           → normal authentication demo
 *   java pqkerberos.Demo attacks   → run attack scenarios after normal auth
 */
public class Demo {

    public static final String SERVICE_NAME = "fileservice@PQKERBEROS.REALM";
    public static final int    SERVICE_PORT = 9999;
    public static final String KDC_HOST     = "localhost";

    // ANSI colours (works in IntelliJ terminal and Windows Terminal)
    static final String GRN = "\u001B[32m", YLW = "\u001B[33m",
            CYN = "\u001B[36m", BLD = "\u001B[1m", RST = "\u001B[0m";

    public static void main(String[] args) throws Exception {
        boolean runAttacks = args.length > 0 && args[0].equalsIgnoreCase("attacks");

        printBanner();

        // ── Phase 1: KDC ────────────────────────────────────────────────
        printPhase(1, "KDC STARTUP");
        DemoKDC kdc = new DemoKDC();
        kdc.initialize();

        new Thread(() -> {
            try { kdc.start(); }
            catch (IOException e) { System.err.println("KDC: " + e.getMessage()); }
        }, "KDC-Thread").start();

        TimeUnit.MILLISECONDS.sleep(600);
        printInfo("KDC listening: AS=8888, TGS=8889");

        // ── Phase 2: FileService ─────────────────────────────────────────
        printPhase(2, "SERVICE STARTUP");
        byte[] serviceKey = kdc.getServiceKeyForDemo(SERVICE_NAME);
        FileService fileService = new FileService(
                SERVICE_NAME, SERVICE_PORT, serviceKey, kdc.getSigningPublicKey());

        new Thread(() -> {
            try { fileService.start(); }
            catch (IOException e) { System.err.println("Service: " + e.getMessage()); }
        }, "Service-Thread").start();

        TimeUnit.MILLISECONDS.sleep(400);
        printInfo("FileService listening on port 9999");

        // ── Phase 3: Normal Authentication ──────────────────────────────
        printPhase(3, "NORMAL AUTHENTICATION FLOW (alice → fileservice)");
        printExplain(
                "WHAT IS HAPPENING:",
                "Alice wants to access the file service. She must first prove her identity",
                "to the KDC (Key Distribution Center). The KDC acts as a trusted third party.",
                "No passwords are ever sent to the service. Instead, cryptographic tickets prove identity."
        );

        PQKerberosClient alice = new PQKerberosClient(
                "alice@PQKERBEROS.REALM", KDC_HOST, kdc.getSigningPublicKey());

        try {
            APResponse response = alice.authenticateAndAccess(
                    SERVICE_NAME, KDC_HOST, SERVICE_PORT,
                    "LIST /home/alice/documents".getBytes());

            // ── Results ─────────────────────────────────────────────────
            printPhase(4, "AUTHENTICATION RESULT");
            printResult("Authentication", response.success ? GRN + "SUCCESS ✓" + RST : "FAILED ✗");
            printResult("Mutual auth   ", response.encryptedClientTimestampPlusOne != null
                    ? GRN + "PROVIDED ✓" + RST : "not provided");
            printResult("Service reply ", response.message);
            if (response.responsePayload != null)
                printResult("Data received ", new String(response.responsePayload));

            printPhase(5, "WHAT JUST HAPPENED — STEP BY STEP");
            printSteps();

        } catch (Exception e) {
            System.out.println("\n[Demo] Auth failed: " + e.getMessage());
            e.printStackTrace();
        }

        // ── Security Summary ────────────────────────────────────────────
        printPhase(6, "SECURITY PROPERTIES ACHIEVED");
        printSecuritySummary();

        // ── Optional: Attack Demo ────────────────────────────────────────
        if (runAttacks) {
            printPhase(7, "ATTACK SCENARIOS");
            printExplain(
                    "WHAT IS HAPPENING:",
                    "We now simulate real attacks against the running protocol.",
                    "Each attack shows WHAT was tried, WHY it fails, and WHICH code stops it.",
                    "The KDC and FileService are still running from Phases 1 and 2."
            );
            TimeUnit.MILLISECONDS.sleep(500);
            // Pass KDC signing key so AttackSimulator can verify/forge signatures
            AttackSimulator.runAllAttacks(kdc.getSigningPublicKey());
        } else {
            System.out.println("\n" + YLW + "Tip: Run with argument 'attacks' to see attack scenarios:" + RST);
            System.out.println("     java pqkerberos.Demo attacks\n");
        }

        TimeUnit.SECONDS.sleep(2);
    }

    // ── Output helpers ────────────────────────────────────────────────────

    private static void printBanner() {
        System.out.println(BLD + CYN);
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║     PQ-Kerberos — Post-Quantum Authentication Demo       ║");
        System.out.println("║  ML-KEM  Kyber-768    NIST FIPS 203 — Key Exchange       ║");
        System.out.println("║  ML-DSA  Dilithium-3  NIST FIPS 204 — Signatures         ║");
        System.out.println("║  AES-256-GCM          NIST FIPS 197 — Symmetric Encrypt  ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println(RST);
    }

    private static void printPhase(int n, String title) {
        System.out.println("\n" + BLD + "═══ PHASE " + n + ": " + title + " ═══" + RST);
    }

    private static void printInfo(String msg) {
        System.out.println(GRN + "  [✓] " + msg + RST);
    }

    private static void printResult(String label, String value) {
        System.out.printf("  %-16s: %s%n", label, value);
    }

    private static void printExplain(String heading, String... lines) {
        System.out.println("\n  " + YLW + heading + RST);
        for (String l : lines) System.out.println("  " + l);
        System.out.println();
    }

    private static void printSteps() {
        String[][] steps = {
                {"Step 1 (AS-REQ)", "Alice sends her identity + Kyber-768 public key to KDC"},
                {"Step 2 (AS-REP)", "KDC generates a session key, encapsulates it with Alice's Kyber key"},
                {"             ",   "KDC issues a TGT (encrypted with KDC's master key — Alice cannot open it)"},
                {"             ",   "KDC signs the response with Dilithium-3 → Alice verifies ✓"},
                {"Step 3 (TGS-REQ)","Alice presents the TGT + authenticator to KDC Ticket Granting Server"},
                {"Step 4 (TGS-REP)","TGS decrypts TGT (proves it's genuine), issues service ticket"},
                {"             ",   "Service ticket encrypted with FileService's long-term key"},
                {"Step 5 (AP-REQ)", "Alice sends service ticket + authenticator to FileService"},
                {"Step 6 (AP-REP)", "FileService decrypts ticket (proves genuine), verifies authenticator"},
                {"             ",   "Returns timestamp+1 encrypted with session key → mutual auth proof"},
        };
        for (String[] step : steps) {
            System.out.printf("  " + CYN + "%-18s" + RST + " %s%n", step[0], step[1]);
        }
    }

    private static void printSecuritySummary() {
        Object[][] props = {
                {"Confidentiality  ", "AES-256-GCM on ALL tickets and session keys"},
                {"Integrity        ", "GCM 128-bit authentication tag + Dilithium-3 signatures"},
                {"Authentication   ", "KDC issues signed TGT; service decrypts with its own key"},
                {"Mutual auth      ", "Service proves it decrypted the ticket (timestamp+1)"},
                {"Non-repudiation  ", "KDC-signed tickets are cryptographic audit evidence"},
                {"Replay protection", "Per-request nonces + timestamps + server-side replay cache"},
                {"Quantum-safe     ", "No RSA/ECC anywhere; Kyber-768 + Dilithium-3 throughout"},
        };
        for (Object[] p : props) {
            System.out.printf("  " + GRN + "✓" + RST + " %-20s — %s%n", p[0], p[1]);
        }
        System.out.println("\n  Algorithms:");
        System.out.println("    Key exchange : ML-KEM  Kyber-768    (NIST FIPS 203, Security Level 3)");
        System.out.println("    Signatures   : ML-DSA  Dilithium-3  (NIST FIPS 204, Security Level 3)");
        System.out.println("    Symmetric    : AES-256-GCM          (Grover-resistant, 128-bit QSec)");
        System.out.println("    Key derivation: HKDF-SHA256         (RFC 5869, hash-based, QS)");
    }

    // ── DemoKDC inner class ───────────────────────────────────────────────

    static class DemoKDC extends KDCServer {
        // KDCServer already has getServiceKeyForDemo() and getSigningPublicKey()
        // initialize() and start() are inherited
    }
}