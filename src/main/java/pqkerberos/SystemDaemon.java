package pqkerberos;

import java.io.*;
import java.util.concurrent.TimeUnit;

/**
 * SystemDaemon — Starts the entire PQ-Kerberos infrastructure in one JVM.
 *
 *   Component    Port    Role
 *   ─────────────────────────────────────────────────────────
 *   KDC AS       8888    Issues TGTs (Ticket Granting Tickets)
 *   KDC TGS      8889    Issues service tickets
 *   FileService  9999    Example protected resource
 *   PAM Daemon   7777    Bridges Linux PAM → full Kerberos exchange
 *
 * USAGE:
 *   java -jar pqkerberos.jar                     # daemon mode
 *   java -cp pqkerberos.jar pqkerberos.Demo      # one-shot demo
 *   java -cp pqkerberos.jar pqkerberos.Demo attacks  # + attack demo
 *
 * DEFAULT USERS (password in /etc/pqkerberos/users.conf overrides these):
 *   alice / alice123
 *   bob   / bob456
 */
public class SystemDaemon {

    // ── Configuration ─────────────────────────────────────────────────────
    public static final String REALM        = "PQKERBEROS.REALM";
    public static final String SERVICE_NAME = "fileservice@" + REALM;
    public static final int    SERVICE_PORT = 9999;
    public static final String KDC_HOST     = "localhost";
    public static final String SERVICE_HOST = "localhost";

    private static final String CONFIG_FILE = "/etc/pqkerberos/users.conf";

    /** Fallback demo users — loaded if /etc/pqkerberos/users.conf is absent. */
    private static final String[][] DEFAULT_USERS = {
            { "alice", "alice123" },
            { "bob",   "bob456"   },
    };

    // ── ANSI ──────────────────────────────────────────────────────────────
    private static final String GRN = "\u001B[32m", CYN = "\u001B[36m",
            YLW = "\u001B[33m", BLD = "\u001B[1m",  RST = "\u001B[0m";

    // ── Entry point ───────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        printBanner();

        // ── 1. KDC ────────────────────────────────────────────────────────
        System.out.println(BLD + "[System] Starting KDC..." + RST);
        KDCServer kdc = new KDCServer();
        kdc.initialize();

        Thread kdcThread = new Thread(() -> {
            try { kdc.start(); }
            catch (IOException e) { System.err.println("[KDC] Fatal: " + e.getMessage()); }
        }, "KDC-Thread");
        kdcThread.setDaemon(true);
        kdcThread.start();

        TimeUnit.MILLISECONDS.sleep(800);
        System.out.println(GRN + "[System] ✓ KDC running — AS:8888  TGS:8889" + RST);

        // ── 2. FileService ────────────────────────────────────────────────
        System.out.println(BLD + "[System] Starting FileService..." + RST);
        byte[] serviceKey = kdc.getServiceKeyForDemo(SERVICE_NAME);
        FileService fileService = new FileService(
                SERVICE_NAME, SERVICE_PORT, serviceKey, kdc.getSigningPublicKey());

        Thread svcThread = new Thread(() -> {
            try { fileService.start(); }
            catch (IOException e) { System.err.println("[Service] Fatal: " + e.getMessage()); }
        }, "FileService-Thread");
        svcThread.setDaemon(true);
        svcThread.start();

        TimeUnit.MILLISECONDS.sleep(500);
        System.out.println(GRN + "[System] ✓ FileService running — port:" + SERVICE_PORT + RST);

        // ── 3. PAM Auth Daemon ─────────────────────────────────────────────
        System.out.println(BLD + "[System] Starting PAM Auth Daemon..." + RST);
        PAMAuthDaemon pamDaemon = new PAMAuthDaemon(
                kdc, KDC_HOST, SERVICE_HOST, SERVICE_PORT, REALM, SERVICE_NAME);

        // Load users from config file if present; fall back to defaults
        File configFile = new File(CONFIG_FILE);
        if (configFile.exists()) {
            System.out.println("[System] Loading users from " + CONFIG_FILE);
            pamDaemon.loadPasswordFile(CONFIG_FILE);
        } else {
            System.out.println(YLW + "[System] " + CONFIG_FILE + " not found — using default demo users" + RST);
            for (String[] u : DEFAULT_USERS) {
                pamDaemon.addUser(u[0], u[1]);
            }
        }

        Thread pamThread = new Thread(() -> {
            try { pamDaemon.start(); }
            catch (IOException e) { System.err.println("[PAMDaemon] Fatal: " + e.getMessage()); }
        }, "PAM-Daemon-Thread");
        pamThread.setDaemon(true);
        pamThread.start();

        TimeUnit.MILLISECONDS.sleep(400);
        System.out.println(GRN + "[System] ✓ PAM Daemon running — 127.0.0.1:7777" + RST);

        // ── Status board ──────────────────────────────────────────────────
        System.out.println();
        printStatus();

        // Keep the main thread alive — all service threads are daemon threads
        Thread.currentThread().join();
    }

    // ── Formatting helpers ────────────────────────────────────────────────

    private static void printBanner() {
        System.out.println(BLD + CYN);
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║   PQ-Kerberos System Daemon                              ║");
        System.out.println("║   Post-Quantum Authentication Infrastructure             ║");
        System.out.println("║                                                          ║");
        System.out.println("║   ML-KEM  Kyber-768    NIST FIPS 203 (Level 3)          ║");
        System.out.println("║   ML-DSA  Dilithium-3  NIST FIPS 204 (Level 3)          ║");
        System.out.println("║   AES-256-GCM          NIST FIPS 197 / SP 800-38D       ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println(RST);
    }

    private static void printStatus() {
        System.out.println(BLD + "Services:" + RST);
        System.out.println("  KDC AS      → localhost:8888");
        System.out.println("  KDC TGS     → localhost:8889");
        System.out.println("  FileService → localhost:9999");
        System.out.println("  PAM Socket  → 127.0.0.1:7777  (loopback only)");
        System.out.println();
        System.out.println(BLD + "Test commands (in another terminal):" + RST);
        System.out.println("  pqkerberos-login alice           # interactive login demo");
        System.out.println("  pqkerberos-login bob             # second user");
        System.out.println("  pamtester pqkerberos alice authenticate  # PAM stack test");
        System.out.println("  java -cp pqkerberos.jar pqkerberos.Demo attacks  # attack demo");
        System.out.println();
        System.out.println(YLW + "Logs appear in this terminal as clients connect." + RST);
        System.out.println();
    }
}
