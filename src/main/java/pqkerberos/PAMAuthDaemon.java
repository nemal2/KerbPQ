package pqkerberos;

import pqkerberos.ProtocolMessages.*;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.*;

/**
 * PAMAuthDaemon — Bridges Linux PAM to the PQ-Kerberos protocol.
 *
 * Listens on TCP 127.0.0.1:7777 (loopback only — never expose externally).
 *
 * WIRE PROTOCOL (plain text, newline-terminated):
 *   Request:  "username:password\n"
 *   Response: "OK:principal@REALM\n"    — success
 *             "FAIL:reason\n"           — failure
 *
 * WHAT HAPPENS ON EACH AUTH REQUEST:
 *   1. Parse username:password from the PAM module.
 *   2. Look up the password in the local in-memory store
 *      (loaded from /etc/pqkerberos/users.conf or added programmatically).
 *   3. Perform a FULL PQ-Kerberos exchange:
 *         AS-REQ  → KDC:8888  (Kyber-768 key exchange + TGT)
 *         TGS-REQ → KDC:8889  (service ticket)
 *         AP-REQ  → FileService:9999 (mutual auth)
 *   4. Return OK or FAIL.
 *
 * The daemon output shows every step of the exchange so you can watch
 * the full post-quantum protocol in the terminal while PAM is authenticating.
 */
public class PAMAuthDaemon {

    public static final int  PAM_PORT   = 7777;
    public static final String BIND_HOST = "127.0.0.1";

    // ANSI colours for terminal output
    private static final String GRN = "\u001B[32m", RED = "\u001B[31m",
            CYN = "\u001B[36m", YLW = "\u001B[33m", RST = "\u001B[0m";

    private final KDCServer   kdc;
    private final String      kdcHost;
    private final String      serviceHost;
    private final int         servicePort;
    private final String      realm;
    private final String      serviceName;

    /** username → cleartext password (demo only — in production use salted hash) */
    private final Map<String, String> passwordStore = new ConcurrentHashMap<>();

    public PAMAuthDaemon(KDCServer kdc,
                          String kdcHost, String serviceHost,
                          int servicePort, String realm, String serviceName) {
        this.kdc         = kdc;
        this.kdcHost     = kdcHost;
        this.serviceHost = serviceHost;
        this.servicePort = servicePort;
        this.realm       = realm;
        this.serviceName = serviceName;
    }

    /** Add a user to the password store and register them in the KDC. */
    public void addUser(String username, String password) {
        passwordStore.put(username, password);
        // Also register the principal with the KDC so AS-REQ succeeds
        kdc.addKerberosUser(username + "@" + realm);
    }

    /**
     * Load users from a Java .properties file:
     *   alice=alice123
     *   bob=bob456
     */
    public void loadPasswordFile(String path) throws IOException {
        Properties props = new Properties();
        try (FileReader r = new FileReader(path)) {
            props.load(r);
        }
        for (String name : props.stringPropertyNames()) {
            addUser(name, props.getProperty(name));
        }
        System.out.println("[PAMDaemon] Loaded " + passwordStore.size()
                + " users from " + path);
    }

    /** Start listening. Blocks forever (call from a dedicated thread). */
    public void start() throws IOException {
        ServerSocket serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(
                InetAddress.getByName(BIND_HOST), PAM_PORT));

        System.out.println(CYN + "[PAMDaemon] Listening on "
                + BIND_HOST + ":" + PAM_PORT + RST);
        System.out.println("[PAMDaemon] Registered users: " + passwordStore.keySet());

        ExecutorService pool = Executors.newCachedThreadPool();
        while (true) {
            Socket client = serverSocket.accept();
            pool.submit(() -> handleRequest(client));
        }
    }

    // ── Per-connection handler ────────────────────────────────────────────

    private void handleRequest(Socket socket) {
        String remoteAddr = socket.getRemoteSocketAddress().toString();
        try {
            socket.setSoTimeout(15_000);

            BufferedReader  in  = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            PrintWriter     out = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream()), true);

            String line = in.readLine();
            if (line == null || !line.contains(":")) {
                out.println("FAIL:Bad request format — expected username:password");
                return;
            }

            int sep = line.indexOf(':');
            String username = line.substring(0, sep);
            String password = line.substring(sep + 1);

            System.out.println("\n[PAMDaemon] ── Auth request ──────────────────────────");
            System.out.println("[PAMDaemon] User     : " + username);
            System.out.println("[PAMDaemon] From     : " + remoteAddr);

            // ── Step 1: Password check ────────────────────────────────────
            String stored = passwordStore.get(username);
            if (stored == null) {
                System.out.println(RED + "[PAMDaemon] FAIL — unknown user: " + username + RST);
                out.println("FAIL:Unknown user");
                return;
            }
            if (!stored.equals(password)) {
                System.out.println(RED + "[PAMDaemon] FAIL — wrong password for: " + username + RST);
                out.println("FAIL:Authentication failed");
                return;
            }
            System.out.println(GRN + "[PAMDaemon] Password OK — starting PQ-Kerberos exchange" + RST);

            // ── Step 2: Full PQ-Kerberos exchange ─────────────────────────
            String principal  = username + "@" + realm;
            PublicKey kdcKey  = kdc.getSigningPublicKey();
            PQKerberosClient client = new PQKerberosClient(principal, kdcHost, kdcKey);

            try {
                APResponse response = client.authenticateAndAccess(
                        serviceName,
                        serviceHost,
                        servicePort,
                        ("PAM_AUTH_CHECK:" + username).getBytes());

                if (response.success) {
                    System.out.println(GRN
                            + "[PAMDaemon] ✓ SUCCESS — full Kerberos exchange completed for "
                            + principal + RST);
                    out.println("OK:" + principal);
                } else {
                    System.out.println(RED + "[PAMDaemon] ✗ Service rejected: "
                            + response.message + RST);
                    out.println("FAIL:" + response.message);
                }

            } catch (SecurityException e) {
                // Signature verification failed → MITM or config error
                System.out.println(RED + "[PAMDaemon] ✗ SECURITY EXCEPTION: " + e.getMessage() + RST);
                out.println("FAIL:Security error — " + e.getMessage());
            } catch (Exception e) {
                System.out.println(YLW + "[PAMDaemon] Kerberos exchange error: "
                        + e.getMessage() + RST);
                out.println("FAIL:Kerberos exchange failed");
            }

        } catch (Exception e) {
            System.err.println("[PAMDaemon] Handler error: " + e.getMessage());
            try {
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.println("FAIL:Internal server error");
            } catch (IOException ignored) {}
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }
}
