package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.auth.RoleAccessControl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CiphertextFormat;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.DefaultCryptoCodec;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.InMemoryNonceTracker;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProviderImpl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.NonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.SecureRandomNonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.InMemoryKeyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发场景：
 * 1) 多线程轮换 + 多线程加密同时进行：版本号严格单调无重复，密文全部可解密，
 *    且同一 KEK 版本下不出现 nonce 复用；
 * 2) 确定性注入：同一版本下第二次提交相同包装 nonce，必须 NONCE_REUSE_DETECTED，
 *    且不会产出任何密文。
 */
class EnvelopeConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeConcurrencyTest.class);

    private final Caller admin = new Caller("svc-admin",
            EnumSet.of(Role.ENCRYPTOR, Role.DECRYPTOR, Role.ROTATOR));

    /** 可脚本化的 nonce 生成器：默认走安全随机；也可强制返回固定 nonce。 */
    private static final class ScriptedNonceGenerator implements NonceGenerator {
        private final NonceGenerator delegate = new SecureRandomNonceGenerator();
        private final List<byte[]> scripted = Collections.synchronizedList(new ArrayList<>());
        private final AtomicInteger idx = new AtomicInteger();

        void forceNext(byte[] nonce) {
            scripted.add(nonce.clone());
        }

        @Override
        public byte[] generate() {
            int i = idx.getAndIncrement();
            if (i < scripted.size()) {
                return scripted.get(i).clone();
            }
            return delegate.generate();
        }
    }

    private DefaultEnvelopeService newService(NonceGenerator nonceGenerator) {
        var provider = new LocalKeyMaterialProviderImpl();
        return new DefaultEnvelopeService(
                new InMemoryKeyStore(provider),
                new DefaultCryptoCodec(),
                nonceGenerator,
                new InMemoryNonceTracker(),
                provider,
                new RoleAccessControl(),
                new InMemoryAuditLog(),
                new CiphertextFormat());
    }

    @Test
    void concurrentRotationsAndEncryptionStayConsistent() throws Exception {
        DefaultEnvelopeService svc = newService(new SecureRandomNonceGenerator());
        int rotators = 4;
        int encryptors = 8;
        int encryptsPerThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(rotators + encryptors);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        List<byte[]> ciphertexts = Collections.synchronizedList(new ArrayList<>());
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());

        for (int r = 0; r < rotators; r++) {
            pool.submit(() -> {
                try {
                    start.await();
                    svc.rotate(admin);
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        for (int e = 0; e < encryptors; e++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int k = 0; k < encryptsPerThread; k++) {
                        byte[] cipher = svc.encrypt(admin,
                                ("concurrent-" + Thread.currentThread().getId() + "-" + k)
                                        .getBytes(StandardCharsets.UTF_8));
                        ciphertexts.add(cipher);
                        success.incrementAndGet();
                    }
                } catch (EnvelopeException ex) {
                    rejected.incrementAndGet();
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "线程应在时限内结束");

        // 所有产生的密文都必须能解开（允许落在轮换前或轮换后的版本）
        int decryptable = 0;
        for (byte[] c : ciphertexts) {
            svc.decrypt(admin, c);
            decryptable++;
        }
        // 轮换串行化：rotators 次轮换恰好产生 rotators 个新版本，版本号为 2..rotators+1
        Set<Integer> versions = new HashSet<>();
        svc.versions().forEach(kv -> versions.add(kv.getVersion()));
        long activeCount = svc.versions().stream()
                .filter(kv -> kv.getStatus()
                        == com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyStatus.ACTIVE)
                .count();

        log.info("[TEST-JUDGE] scenario=concurrent-rotate encryptSuccess={} encryptRejected={} ciphertexts={} allDecryptable={} versionCount={} activeCount={} unexpectedErrors={}",
                success.get(), rejected.get(), ciphertexts.size(), decryptable == ciphertexts.size(),
                versions.size(), activeCount, errors.size());
        assertTrue(errors.isEmpty(), "不应出现非预期异常: " + errors);
        assertEquals(encryptors * encryptsPerThread, ciphertexts.size(),
                "正常安全随机下不应有加密被拒绝");
        assertEquals(rotators + 1, versions.size(), "并发轮换必须串行且无重复版本号");
        assertEquals(1, activeCount, "任意时刻只能有一个 ACTIVE 版本");
        assertEquals(ciphertexts.size(), decryptable, "轮换期间产生的密文必须全部可解密");
    }

    @Test
    void reusedNonceUnderSameKeyVersionIsRejectedAndProducesNoCiphertext() {
        ScriptedNonceGenerator gen = new ScriptedNonceGenerator();
        DefaultEnvelopeService svc = newService(gen);

        // 每次加密取两个 nonce（dataNonce、wrapNonce）。
        // 让第 2 次加密的 wrapNonce 与第 1 次完全相同，dataNonce 不同。
        byte[] fixedWrap = new byte[12];
        for (int i = 0; i < 12; i++) {
            fixedWrap[i] = (byte) (0xA0 + i);
        }
        byte[] data1 = new byte[12];
        byte[] data2 = new byte[12];
        for (int i = 0; i < 12; i++) {
            data1[i] = (byte) (0x10 + i);
            data2[i] = (byte) (0x20 + i);
        }
        gen.forceNext(data1);   // 第一次 dataNonce
        gen.forceNext(fixedWrap); // 第一次 wrapNonce
        gen.forceNext(data2);   // 第二次 dataNonce（不同）
        gen.forceNext(fixedWrap); // 第二次 wrapNonce（与第一次同版本复用！）

        byte[] first = svc.encrypt(admin, "first".getBytes(StandardCharsets.UTF_8));
        log.info("[TEST-INPUT] scenario=nonce-reuse firstCiphertextLen={} reusedWrapNonce=A0..AB",
                first.length);

        EnvelopeException ex = null;
        try {
            svc.encrypt(admin, "second".getBytes(StandardCharsets.UTF_8));
        } catch (EnvelopeException e) {
            ex = e;
        }
        log.info("[TEST-JUDGE] scenario=nonce-reuse rejected={} reason={} firstCiphertextStillDecryptable={}",
                ex != null, ex == null ? "NONE" : ex.getReason(),
                new String(svc.decrypt(admin, first), StandardCharsets.UTF_8).equals("first"));
        assertEquals(RejectReason.NONCE_REUSE_DETECTED, ex == null ? null : ex.getReason(),
                "同一 KEK 版本下 nonce 复用必须明确拒绝");
        assertEquals("first", new String(svc.decrypt(admin, first), StandardCharsets.UTF_8),
                "复用检测不得影响此前已产出的密文");
    }
}
