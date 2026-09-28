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
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyStatus;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyVersion;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.InMemoryKeyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 基础往返、历史密文兼容、停用版本只解密不加密。
 */
class EnvelopeRoundTripTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeRoundTripTest.class);

    private final Caller allRoles = new Caller("svc-full",
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

    @Test
    void encryptThenDecryptReturnsPlaintext() {
        DefaultEnvelopeService svc = newService();
        byte[] plaintext = "本地信封加密-往返测试".getBytes(StandardCharsets.UTF_8);
        log.info("[TEST-INPUT] scenario=roundtrip plaintextLen={}", plaintext.length);

        byte[] cipher = svc.encrypt(allRoles, plaintext);
        byte[] restored = svc.decrypt(allRoles, cipher);

        log.info("[TEST-JUDGE] scenario=roundtrip ciphertextLen={} plaintextMatch={}",
                cipher.length, java.util.Arrays.equals(plaintext, restored));
        assertArrayEquals(plaintext, restored);
    }

    @Test
    void historicalCiphertextSurvivesRotation() {
        DefaultEnvelopeService svc = newService();
        byte[] oldPlaintext = "rotation-before".getBytes(StandardCharsets.UTF_8);
        byte[] oldCipher = svc.encrypt(allRoles, oldPlaintext);
        int oldVersion = svc.versions().stream()
                .filter(kv -> kv.getStatus() == KeyStatus.ACTIVE).findFirst().orElseThrow()
                .getVersion();

        int newVersion = svc.rotate(allRoles);
        byte[] newPlaintext = "rotation-after".getBytes(StandardCharsets.UTF_8);
        byte[] newCipher = svc.encrypt(allRoles, newPlaintext);

        byte[] oldRestored = svc.decrypt(allRoles, oldCipher);
        byte[] newRestored = svc.decrypt(allRoles, newCipher);
        List<KeyVersion> versions = svc.versions();

        log.info("[TEST-JUDGE] scenario=rotation oldVersion={} newVersion={} oldDecryptable={} newDecryptable={} versionCount={}",
                oldVersion, newVersion,
                java.util.Arrays.equals(oldPlaintext, oldRestored),
                java.util.Arrays.equals(newPlaintext, newRestored), versions.size());
        assertEquals(oldVersion + 1, newVersion);
        assertArrayEquals(oldPlaintext, oldRestored, "历史版本密文轮换后仍可解密");
        assertArrayEquals(newPlaintext, newRestored, "新数据走新版本");
        assertEquals(2, versions.size());
        assertEquals(KeyStatus.DISABLED,
                versions.get(0).getStatus());
        assertEquals(KeyStatus.ACTIVE,
                versions.get(1).getStatus());
    }

    @Test
    void multipleRotationsKeepAllHistoryReadable() {
        DefaultEnvelopeService svc = newService();
        byte[] p1 = svc.encrypt(allRoles, "v1-data".getBytes(StandardCharsets.UTF_8));
        svc.rotate(allRoles);
        byte[] p2 = svc.encrypt(allRoles, "v2-data".getBytes(StandardCharsets.UTF_8));
        svc.rotate(allRoles);
        byte[] p3 = svc.encrypt(allRoles, "v3-data".getBytes(StandardCharsets.UTF_8));

        log.info("[TEST-JUDGE] scenario=multi-rotate versions={} v1Readable={} v2Readable={} v3Readable={}",
                svc.versions().size(),
                new String(svc.decrypt(allRoles, p1), StandardCharsets.UTF_8).equals("v1-data"),
                new String(svc.decrypt(allRoles, p2), StandardCharsets.UTF_8).equals("v2-data"),
                new String(svc.decrypt(allRoles, p3), StandardCharsets.UTF_8).equals("v3-data"));
        assertEquals("v1-data", new String(svc.decrypt(allRoles, p1), StandardCharsets.UTF_8));
        assertEquals("v2-data", new String(svc.decrypt(allRoles, p2), StandardCharsets.UTF_8));
        assertEquals("v3-data", new String(svc.decrypt(allRoles, p3), StandardCharsets.UTF_8));
        assertTrue(svc.versions().stream()
                .noneMatch(kv -> kv.getStatus() == KeyStatus.ACTIVE && kv.getVersion() != 3));
    }
}
