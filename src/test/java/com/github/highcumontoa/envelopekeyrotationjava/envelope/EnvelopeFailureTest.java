package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.auth.RoleAccessControl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CiphertextFormat;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.DefaultCryptoCodec;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.InMemoryNonceTracker;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProviderImpl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.SecureRandomNonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.EnvelopeCiphertext;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.InMemoryKeyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 异常路径的可区分拒绝原因：
 * 篡改数据段/包装 DEK -> AUTH_TAG_MISMATCH；
 * 改版本号指向不存在版本 -> VERSION_NOT_FOUND；
 * 魔数/截断损坏 -> CIPHERTEXT_MALFORMED；
 * 换库（密钥对不上）-> AUTH_TAG_MISMATCH。
 */
class EnvelopeFailureTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeFailureTest.class);

    private final Caller admin = new Caller("svc-admin",
            EnumSet.of(Role.ENCRYPTOR, Role.DECRYPTOR, Role.ROTATOR));

    private DefaultEnvelopeService newService() {
        var provider = new LocalKeyMaterialProviderImpl();
        return new DefaultEnvelopeService(
                new InMemoryKeyStore(provider),
                new DefaultCryptoCodec(),
                new SecureRandomNonceGenerator(),
                new InMemoryNonceTracker(),
                provider,
                new RoleAccessControl(),
                new InMemoryAuditLog(),
                new CiphertextFormat());
    }

    private void assertReason(String scenario, RejectReason expected, Runnable action) {
        try {
            action.run();
        } catch (EnvelopeException e) {
            log.info("[TEST-JUDGE] scenario={} expected={} actual={} basis={}",
                    scenario, expected, e.getReason(), e.getMessage());
            assertEquals(expected, e.getReason(), scenario);
            // 底层异常不以消息形式透出：拒绝原因必须是我们的领域枚举
            return;
        }
        throw new AssertionError(scenario + " expected rejection " + expected);
    }

    @Test
    void tamperedDataSegmentIsRejectedAsAuthTagMismatch() {
        DefaultEnvelopeService svc = newService();
        byte[] cipher = svc.encrypt(admin, "secret".getBytes(StandardCharsets.UTF_8));
        byte[] tampered = cipher.clone();
        // 翻转最后一个字节（落在 dataNonce 段），GCM 校验必然失败
        tampered[tampered.length - 1] ^= 0x01;
        log.info("[TEST-INPUT] scenario=tamper-data ciphertextLen={} flippedByte=last", tampered.length);
        assertReason("tamper-data", RejectReason.AUTH_TAG_MISMATCH,
                () -> svc.decrypt(admin, tampered));
    }

    @Test
    void tamperedWrappedDekIsRejectedAsAuthTagMismatch() {
        DefaultEnvelopeService svc = newService();
        CiphertextFormat fmt = new CiphertextFormat();
        byte[] cipher = svc.encrypt(admin, "secret".getBytes(StandardCharsets.UTF_8));
        EnvelopeCiphertext parsed = fmt.decode(cipher);
        byte[] wrapped = parsed.wrappedDek().clone();
        wrapped[0] ^= (byte) 0xFF;
        byte[] rebuilt = fmt.encode(new EnvelopeCiphertext(parsed.kekVersion(), wrapped,
                parsed.dekNonce(), parsed.dataCipher(), parsed.dataNonce()));
        log.info("[TEST-INPUT] scenario=tamper-wrapped-dek version={} wrappedDekLen={}",
                parsed.kekVersion(), wrapped.length);
        assertReason("tamper-wrapped-dek", RejectReason.AUTH_TAG_MISMATCH,
                () -> svc.decrypt(admin, rebuilt));
    }

    @Test
    void rewiringVersionToUnknownVersionIsRejectedAsVersionNotFound() {
        DefaultEnvelopeService svc = newService();
        byte[] cipher = svc.encrypt(admin, "secret".getBytes(StandardCharsets.UTF_8));
        CiphertextFormat fmt = new CiphertextFormat();
        EnvelopeCiphertext parsed = fmt.decode(cipher);
        // 只改版本号，段内容不动：指向不存在的版本
        byte[] rebuilt = fmt.encode(new EnvelopeCiphertext(999,
                parsed.wrappedDek(), parsed.dekNonce(),
                parsed.dataCipher(), parsed.dataNonce()));
        log.info("[TEST-INPUT] scenario=version-missing actualVersion={} forgedVersion=999",
                parsed.kekVersion());
        assertReason("version-missing", RejectReason.VERSION_NOT_FOUND,
                () -> svc.decrypt(admin, rebuilt));
    }

    @Test
    void garbageBytesAreRejectedAsMalformed() {
        DefaultEnvelopeService svc = newService();
        byte[] garbage = "this-is-not-an-envelope".getBytes(StandardCharsets.UTF_8);
        log.info("[TEST-INPUT] scenario=malformed bytesLen={}", garbage.length);
        assertReason("malformed", RejectReason.CIPHERTEXT_MALFORMED,
                () -> svc.decrypt(admin, garbage));

        byte[] truncated = new byte[]{(byte) 'E', (byte) 'N', (byte) 'V', (byte) '1', 0, 0, 0};
        assertReason("truncated", RejectReason.CIPHERTEXT_MALFORMED,
                () -> svc.decrypt(admin, truncated));
    }

    @Test
    void differentKeystoreMeansKeyMismatch() {
        DefaultEnvelopeService svcA = newService();
        DefaultEnvelopeService svcB = newService(); // 独立密钥库，KEK 完全不同
        byte[] cipher = svcA.encrypt(admin, "secret".getBytes(StandardCharsets.UTF_8));
        log.info("[TEST-INPUT] scenario=key-mismatch ciphertext produced by keystore-A, decrypted by keystore-B");
        // 版本号相同(1)但密钥对不上：必须报认证失败而不是解出乱码
        assertReason("key-mismatch", RejectReason.AUTH_TAG_MISMATCH,
                () -> svcB.decrypt(admin, cipher));
    }
}
