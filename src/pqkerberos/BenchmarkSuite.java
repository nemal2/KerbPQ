package pqkerberos;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class BenchmarkSuite {

    private static final int PQ_ITERATIONS = 100;
    private static final int AES_ITERATIONS = 500;

    public static void main(String[] args) throws Exception {

        System.out.println("=================================================");
        System.out.println("         PQ-KERBEROS BENCHMARK SUITE");
        System.out.println("=================================================\n");

        benchmarkKyber();
        benchmarkDilithium();
        benchmarkAES();

        System.out.println("\nBenchmark complete.");
    }

    // =========================================================
    // KYBER BENCHMARKS
    // =========================================================

    private static void benchmarkKyber() throws Exception {

        System.out.println("-------------------------------------------------");
        System.out.println("KYBER-768 BENCHMARK");
        System.out.println("-------------------------------------------------");

        List<Double> keygenTimes = new ArrayList<>();
        List<Double> encapsTimes = new ArrayList<>();
        List<Double> decapsTimes = new ArrayList<>();

        for (int i = 0; i < PQ_ITERATIONS; i++) {

            // Key Generation
            long start = System.nanoTime();

            KeyPair kp = PQCrypto.generateKEMKeyPair();

            long end = System.nanoTime();

            keygenTimes.add(toMillis(start, end));

            // Encapsulation
            start = System.nanoTime();

            PQCrypto.KEMResult result =
                    PQCrypto.encapsulate(kp.getPublic());

            end = System.nanoTime();

            encapsTimes.add(toMillis(start, end));

            // Decapsulation
            start = System.nanoTime();

            PQCrypto.decapsulate(
                    kp.getPrivate(),
                    result.ciphertext
            );

            end = System.nanoTime();

            decapsTimes.add(toMillis(start, end));
        }

        printStats("Kyber KeyGen", keygenTimes);
        printStats("Kyber Encapsulation", encapsTimes);
        printStats("Kyber Decapsulation", decapsTimes);

        exportCSV("Kyber KeyGen", keygenTimes);
        exportCSV("Kyber Encapsulation", encapsTimes);
        exportCSV("Kyber Decapsulation", decapsTimes);
    }

    // =========================================================
    // DILITHIUM BENCHMARKS
    // =========================================================

    private static void benchmarkDilithium() throws Exception {

        System.out.println("\n-------------------------------------------------");
        System.out.println("DILITHIUM-3 BENCHMARK");
        System.out.println("-------------------------------------------------");

        List<Double> signTimes = new ArrayList<>();
        List<Double> verifyTimes = new ArrayList<>();

        KeyPair signingKeyPair = PQCrypto.generateSigningKeyPair();

        byte[] message = "PQ-Kerberos Benchmark Test".getBytes();

        for (int i = 0; i < PQ_ITERATIONS; i++) {

            // Signing
            long start = System.nanoTime();

            byte[] signature = PQCrypto.sign(
                    message,
                    signingKeyPair.getPrivate()
            );

            long end = System.nanoTime();

            signTimes.add(toMillis(start, end));

            // Verification
            start = System.nanoTime();

            PQCrypto.verify(
                    message,
                    signature,
                    signingKeyPair.getPublic()
            );

            end = System.nanoTime();

            verifyTimes.add(toMillis(start, end));
        }

        printStats("Dilithium Signing", signTimes);
        printStats("Dilithium Verification", verifyTimes);

        exportCSV("Dilithium Signing", signTimes);
        exportCSV("Dilithium Verification", verifyTimes);
    }

    // =========================================================
    // AES BENCHMARKS
    // =========================================================

    private static void benchmarkAES() throws Exception {

        System.out.println("\n-------------------------------------------------");
        System.out.println("AES-256-GCM BENCHMARK");
        System.out.println("-------------------------------------------------");

        benchmarkAESPayload(1024);         // 1KB
        benchmarkAESPayload(10 * 1024);    // 10KB
        benchmarkAESPayload(100 * 1024);   // 100KB
        benchmarkAESPayload(1024 * 1024);  // 1MB
    }

    private static void benchmarkAESPayload(int size) throws Exception {

        List<Double> encryptTimes = new ArrayList<>();
        List<Double> decryptTimes = new ArrayList<>();

        byte[] payload = new byte[size];

        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i % 256);
        }

        byte[] keyBytes = new byte[32];

        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) i;
        }

        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        for (int i = 0; i < AES_ITERATIONS; i++) {

            // Encrypt
            long start = System.nanoTime();

            byte[] ciphertext = PQCrypto.encrypt(payload, key);

            long end = System.nanoTime();

            encryptTimes.add(toMillis(start, end));

            // Decrypt
            start = System.nanoTime();

            PQCrypto.decrypt(ciphertext, key);

            end = System.nanoTime();

            decryptTimes.add(toMillis(start, end));
        }

        System.out.println("\nPayload Size: " + readableSize(size));

        printStats("AES Encrypt", encryptTimes);
        printStats("AES Decrypt", decryptTimes);

        exportCSV("AES Encrypt " + readableSize(size), encryptTimes);
        exportCSV("AES Decrypt " + readableSize(size), decryptTimes);
    }

    // =========================================================
    // STATISTICS
    // =========================================================

    private static void printStats(String title, List<Double> values) {

        double avg = average(values);
        double min = min(values);
        double max = max(values);
        double std = stddev(values, avg);

        System.out.println("\n" + title);
        System.out.println("-------------------------------------");
        System.out.printf("Average : %.4f ms%n", avg);
        System.out.printf("Min     : %.4f ms%n", min);
        System.out.printf("Max     : %.4f ms%n", max);
        System.out.printf("Std Dev : %.4f ms%n", std);
        System.out.printf("Ops/sec : %.2f%n", 1000.0 / avg);
    }

    private static double average(List<Double> vals) {

        double sum = 0;

        for (double v : vals) {
            sum += v;
        }

        return sum / vals.size();
    }

    private static double min(List<Double> vals) {

        double min = Double.MAX_VALUE;

        for (double v : vals) {
            if (v < min) min = v;
        }

        return min;
    }

    private static double max(List<Double> vals) {

        double max = Double.MIN_VALUE;

        for (double v : vals) {
            if (v > max) max = v;
        }

        return max;
    }

    private static double stddev(List<Double> vals, double avg) {

        double sum = 0;

        for (double v : vals) {
            sum += Math.pow(v - avg, 2);
        }

        return Math.sqrt(sum / vals.size());
    }

    // =========================================================
    // CSV EXPORT
    // =========================================================

    private static void exportCSV(String testName, List<Double> values) {

        try (PrintWriter pw = new PrintWriter(new FileWriter(
                "benchmark_results.csv", true))) {

            for (double v : values) {
                pw.println(testName + "," + v);
            }

        } catch (Exception e) {
            System.err.println("CSV export failed: " + e.getMessage());
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static double toMillis(long start, long end) {
        return (end - start) / 1_000_000.0;
    }

    private static String readableSize(int size) {

        if (size >= 1024 * 1024) {
            return (size / (1024 * 1024)) + "MB";
        }

        if (size >= 1024) {
            return (size / 1024) + "KB";
        }

        return size + "B";
    }
}