package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.auth.RoleAccessControl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CiphertextFormat;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.DefaultCryptoCodec;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.InMemoryNonceTracker;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProviderImpl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.SecureRandomNonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.InMemoryKeyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 权限矩阵：
 * ENCRYPTOR 仅加密；DECRYPTOR 仅解密；ROTATOR 仅轮换。越权 -> ACCESS_DENIED。
 * 同时校验留痕记录中不含明文与密钥材料。
 */
class EnvelopeAccessControlTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeAccessControlTest.class);

    private final InMemoryAuditLog auditLog = new InMemoryAuditLog();

    private DefaultEnvelopeService newService() {
        var provider = new LocalKeyMaterialProviderImpl();
        return new DefaultEnvelopeService(
                new InMemoryKeyStore(provider),
                new DefaultCryptoCodec(),
                new SecureRandomNonceGenerator(),
                new InMemoryNonceTracker(),
                provider,
                new RoleAccessControl(),
                auditLog,
                new CiphertextFormat());
    }

    private void assertDenied(String scenario, Runnable action) {
        try {
            action.run();
        } catch (EnvelopeException e) {
            log.info("[TEST-JUDGE] scenario={} expected=ACCESS_DENIED actual={}", scenario, e.getReason());
            assertEquals(RejectReason.ACCESS_DENIED, e.getReason(), scenario);
            return;
        }
        throw new AssertionError(scanner(scenario));
    }

    private static String scanner(String scenario) {
        return scenario + " expected ACCESS_DENIED";
    }

    @Test
    void decryptorCannotEncryptOrRotate() {
        DefaultEnvelopeService svc = newService();
        Caller decryptor = new Caller("ro", EnumSet.of(Role.DECRYPTOR));
        log.info("[TEST-INPUT] scenario=decryptor-overreach caller={} roles={}", decryptor.id(), decryptor.roles());
        assertDenied("decryptor-encrypt",
                () -> svc.encrypt(decryptor, "x".getBytes(StandardCharsets.UTF_8)));
        assertDenied("decryptor-rotate", () -> svc.rotate(decryptor));
    }

    @Test
    void encryptorCannotDecryptOrRotate() {
        DefaultEnvelopeService svc = newService();
        Caller encryptor = new Caller("wo", EnumSet.of(Role.ENCRYPTOR));
        byte[] cipher = svc.encrypt(new Caller("ok",
                EnumSet.of(Role.ENCRYPTOR, Role.DECRYPTOR)), "x".getBytes(StandardCharsets.UTF_8));
        log.info("[TEST-INPUT] scenario=encryptor-overreach caller={}", encryptor.id());
        assertDenied("encryptor-decrypt", () -> svc.decrypt(encryptor, cipher));
        assertDenied("encryptor-rotate", () -> svc.rotate(encryptor));
    }

    @Test
    void rotatorCannotEncryptOrDecrypt() {
        DefaultEnvelopeService svc = newService();
        Caller rotator = new Caller("ops", EnumSet.of(Role.ROTATOR));
        byte[] cipher = svc.encrypt(new Caller("ok",
                EnumSet.of(Role.ENCRYPTOR, Role.DECRYPTOR)), "x".getBytes(StandardCharsets.UTF_8));
        log.info("[TEST-INPUT] scenario=rotator-overreach caller={}", rotator.id());
        assertDenied("rotator-encrypt",
                () -> svc.encrypt(rotator, "x".getBytes(StandardCharsets.UTF_8)));
        assertDenied("rotator-decrypt", () -> svc.decrypt(rotator, cipher));
        // 正向：ROTATOR 可以轮换
        assertEquals(2, svc.rotate(rotator));
    }

    @Test
    void anonymousCallerIsRejected() {
        DefaultEnvelopeService svc = newService();
        log.info("[TEST-INPUT] scenario=anonymous caller=null");
        assertDenied("anonymous-encrypt",
                () -> svc.encrypt(null, "x".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void auditTrailRecordsDenialsAndNeverContainsSecrets() {
        DefaultEnvelopeService svc = newService();
        Caller encryptor = new Caller("wo", EnumSet.of(Role.ENCRYPTOR));
        String secret = "PLAINTEXT-SECRET-MARKER";
        byte[] cipher = svc.encrypt(encryptor, secret.getBytes(StandardCharsets.UTF_8));

        // 触发越权解密
        try {
            svc.decrypt(encryptor, cipher);
        } catch (EnvelopeException expected) {
            assertEquals(RejectReason.ACCESS_DENIED, expected.getReason());
        }

        boolean denialFound = auditLog.events().stream()
                .anyMatch(e -> e.action() == AuditAction.ACCESS_DENIED
                        || (!e.success() && e.reason() != null
                        && e.reason().equals(RejectReason.ACCESS_DENIED.name())));
        boolean noPlaintextLeak = auditLog.events().stream()
                .noneMatch(e -> (e.detail() != null && e.detail().contains(secret))
                        || (e.reason() != null && e.reason().contains(secret)));
        log.info("[TEST-JUDGE] scenario=audit eventCount={} denialFound={} noPlaintextLeak={}",
                auditLog.events().size(), denialFound, noPlaintextLeak);
        assertTrue(denialFound, "越权必须留痕");
        assertTrue(noPlaintextLeak, "留痕不得包含明文");
    }
}
