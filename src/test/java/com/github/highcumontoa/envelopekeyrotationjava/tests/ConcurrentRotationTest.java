package com.github.highcumontoa.envelopekeyrotationjava.tests;

import com.github.highcumontoa.envelopekeyrotationjava.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.EnvelopeCipherService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.EnvelopeCiphertext;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.InMemoryKeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyRotationService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.ManagedKey;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.SecureRandomNonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.security.AccessDeniedException;
import com.github.highcumontoa.envelopekeyrotationjava.security.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.security.Role;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发场景：
 * 1) 多线程并发加密同一 ACTIVE 版本，nonce 不得复用、全部密文可解；
 * 2) 多线程并发轮换，版本号必须严格唯一且连续递增；
 * 3) 加密与轮换同时进行，过程中新旧版本共存，所有密文事后可解。
 */
class ConcurrentRotationTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRotationTest.class);

    private final Caller svc = new Caller("svc",
            Set.of(Role.ENCRYPTOR, Role.DECRYPTOR, Role.KEY_ADMIN));

    private record Sealed(byte[] ciphertext, byte[] plaintext, int version) {
    }

    @Test
    void concurrentEncryptionProducesUniqueNoncesAndDecryptableCiphertexts() throws Exception {
        InMemoryAuditLog auditLog = new InMemoryAuditLog();
        InMemoryKeyStore keyStore = new InMemoryKeyStore(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        EnvelopeCipherService cipher = new EnvelopeCipherService(
                keyStore, new SecureRandomNonceGenerator(), auditLog);

        int threads = 16;
        int perThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<List<Sealed>>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int idx = t;
            futures.add(pool.submit(() -> {
                start.await();
                List<Sealed> out = new ArrayList<>();
                for (int i = 0; i < perThread; i++) {
                    byte[] plaintext = ("t" + idx + "-m" + i).getBytes(StandardCharsets.UTF_8);
                    byte[] ct = cipher.encrypt(svc, plaintext);
                    out.add(new Sealed(ct, plaintext, EnvelopeCiphertext.decode(ct).keyVersion()));
                }
                return out;
            }));
        }
        start.countDown();
        Set<String> observedNonces = ConcurrentHashMap.newKeySet();
        List<Sealed> all = new ArrayList<>();
        for (Future<List<Sealed>> f : futures) {
            for (Sealed s : f.get(30, TimeUnit.SECONDS)) {
                all.add(s);
            }
        }
        pool.shutdown();

        // wrappedDek 前 12 字节即 KEK nonce；同一版本下必须全局唯一
        for (Sealed s : all) {
            byte[] nonce = new byte[12];
            System.arraycopy(EnvelopeCiphertext.decode(s.ciphertext()).wrappedDek(),
                    0, nonce, 0, 12);
            String hex = java.util.HexFormat.of().formatHex(nonce);
            assertTrue(observedNonces.add(hex), "duplicate KEK nonce detected: " + hex);
            assertArrayEquals(s.plaintext(), cipher.decrypt(svc, s.ciphertext()));
        }
        log.info("[concurrent-encrypt] decision: {} ciphertexts, {} unique nonces, all verified",
                all.size(), observedNonces.size());
        assertEquals(threads * perThread, all.size());
    }

    @Test
    void concurrentRotationsYieldUniqueMonotonicVersions() throws Exception {
        InMemoryAuditLog auditLog = new InMemoryAuditLog();
        InMemoryKeyStore keyStore = new InMemoryKeyStore(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        KeyRotationService rotation = new KeyRotationService(keyStore, auditLog);

        int rotations = 20;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < rotations; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return rotation.rotate(svc);
            }));
        }
        start.countDown();
        List<Integer> versions = new ArrayList<>();
        for (Future<Integer> f : futures) {
            versions.add(f.get(30, TimeUnit.SECONDS));
        }
        pool.shutdown();

        log.info("[concurrent-rotate] decision: produced versions={}", sorted(versions));
        assertEquals(rotations, new java.util.HashSet<>(versions).size(),
                "duplicate version numbers produced");
        assertEquals(rotations + 1, keyStore.allVersions().size(),
                "old versions must coexist after rotation");
        List<ManagedKey> all = keyStore.allVersions();
        for (int v = 1; v <= rotations; v++) {
            assertEquals(v, all.get(v - 1).version());
        }
        // 只有最后一个版本是 ACTIVE，其余全部 RETIRED 但仍可查
        AtomicInteger activeCount = new AtomicInteger();
        all.forEach(k -> { if (k.state() == com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyState.ACTIVE) activeCount.incrementAndGet(); });
        assertEquals(1, activeCount.get());
    }

    @Test
    void encryptionDuringRotationAlwaysDecryptableAndNonceUnique() throws Exception {
        InMemoryAuditLog auditLog = new InMemoryAuditLog();
        InMemoryKeyStore keyStore = new InMemoryKeyStore(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        EnvelopeCipherService cipher = new EnvelopeCipherService(
                keyStore, new SecureRandomNonceGenerator(), auditLog);
        KeyRotationService rotation = new KeyRotationService(keyStore, auditLog);

        ExecutorService pool = Executors.newFixedThreadPool(10);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> tasks = new ArrayList<>();
        List<Sealed> sealed = Collections.synchronizedList(new ArrayList<>());
        Set<String> nonceByVersion = ConcurrentHashMap.newKeySet();

        for (int i = 0; i < 8; i++) {
            final int idx = i;
            tasks.add(pool.submit(() -> {
                start.await();
                for (int j = 0; j < 25; j++) {
                    byte[] plaintext = ("e" + idx + "-" + j).getBytes(StandardCharsets.UTF_8);
                    byte[] ct = cipher.encrypt(svc, plaintext);
                    int v = EnvelopeCiphertext.decode(ct).keyVersion();
                    byte[] nonce = new byte[12];
                    System.arraycopy(EnvelopeCiphertext.decode(ct).wrappedDek(),
                            0, nonce, 0, 12);
                    nonceByVersion.add(v + ":" + java.util.HexFormat.of().formatHex(nonce));
                    sealed.add(new Sealed(ct, plaintext, v));
                }
                return null;
            }));
        }
        for (int r = 0; r < 5; r++) {
            tasks.add(pool.submit(() -> {
                start.await();
                return rotation.rotate(svc);
            }));
        }
        start.countDown();
        for (Future<?> t : tasks) {
            t.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        assertEquals(sealed.size(), nonceByVersion.size(), "nonce reused across operations");
        for (Sealed s : sealed) {
            assertArrayEquals(s.plaintext(), cipher.decrypt(svc, s.ciphertext()),
                    "ciphertext sealed during rotation must decrypt");
        }
        log.info("[rotate-and-encrypt] decision: {} ciphertexts spread over versions {}, all verified",
                sealed.size(),
                sealed.stream().map(Sealed::version).distinct().sorted().toList());
        assertTrue(sealed.stream().map(Sealed::version).distinct().count() > 1,
                "ciphertexts should span old and new versions");
    }

    @Test
    void nonAdminCannotRotate() {
        InMemoryKeyStore keyStore = new InMemoryKeyStore(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        KeyRotationService rotation = new KeyRotationService(keyStore, new InMemoryAuditLog());
        Caller plainEncryptor = new Caller("enc", Set.of(Role.ENCRYPTOR));
        log.info("[rotate-authz] caller without KEY_ADMIN attempts rotation");
        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> rotation.rotate(plainEncryptor));
        log.info("[rotate-authz] decision: rejected, requiredRole={}", ex.requiredRole());
        assertEquals(Role.KEY_ADMIN.name(), ex.requiredRole());
    }

    private static List<Integer> sorted(List<Integer> values) {
        List<Integer> copy = new ArrayList<>(values);
        Collections.sort(copy);
        return copy;
    }
}
