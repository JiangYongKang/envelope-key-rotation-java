package com.github.highcumontoa.envelopekeyrotationjava.tests;

import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeyrotationjava.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.CiphertextTamperedException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.EnvelopeCipherService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.EnvelopeCiphertext;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.InMemoryKeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyRotationService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.NonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.NonceReuseException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.UnknownKeyVersionException;
import com.github.highcumontoa.envelopekeyrotationjava.security.AccessDeniedException;
import com.github.highcumontoa.envelopekeyrotationjava.security.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.security.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 信封加解密核心场景：当前版本往返、历史版本兼容、
 * 版本不存在、密钥对不上、密文篡改、越权、nonce 复用拒绝。
 */
class EnvelopeCipherServiceTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeCipherServiceTest.class);

    private InMemoryAuditLog auditLog;
    private InMemoryKeyStore keyStore;
    private EnvelopeCipherService cipherService;
    private KeyRotationService rotationService;

    private final Caller encryptor =
            new Caller("enc-1", Set.of(Role.ENCRYPTOR));
    private final Caller decryptor =
            new Caller("dec-1", Set.of(Role.DECRYPTOR));
    private final Caller admin =
            new Caller("admin-1", Set.of(Role.KEY_ADMIN));
    private final Caller allInOne = new Caller("svc",
            Set.of(Role.ENCRYPTOR, Role.DECRYPTOR, Role.KEY_ADMIN));

    @BeforeEach
    void setUp() {
        auditLog = new InMemoryAuditLog();
        keyStore = new InMemoryKeyStore("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        cipherService = new EnvelopeCipherService(
                keyStore, new com.github.highcumontoa.envelopekeyrotationjava.crypto
                        .SecureRandomNonceGenerator(), auditLog);
        rotationService = new KeyRotationService(keyStore, auditLog);
    }

    @Test
    void currentVersionEncryptAndDecryptRoundTrip() {
        byte[] plaintext = "hello envelope encryption".getBytes(StandardCharsets.UTF_8);
        log.info("[round-trip] input plaintext='{}' ({} bytes), currentKeyVersion={}",
                new String(plaintext, StandardCharsets.UTF_8), plaintext.length,
                keyStore.currentKey().orElseThrow().version());

        byte[] ciphertext = cipherService.encrypt(allInOne, plaintext);
        byte[] recovered = cipherService.decrypt(allInOne, ciphertext);

        log.info("[round-trip] decision: ciphertext {} bytes, recovered='{}'",
                ciphertext.length, new String(recovered, StandardCharsets.UTF_8));
        assertArrayEquals(plaintext, recovered);
        assertEquals(1, EnvelopeCiphertext.decode(ciphertext).keyVersion());
    }

    @Test
    void legacyCiphertextRemainsDecryptableAfterRotation() {
        byte[] legacyPlaintext = "sealed under v1".getBytes(StandardCharsets.UTF_8);
        byte[] legacyCiphertext = cipherService.encrypt(allInOne, legacyPlaintext);
        log.info("[compatibility] legacy ciphertext sealed at version={}",
                EnvelopeCiphertext.decode(legacyCiphertext).keyVersion());

        int newVersion = rotationService.rotate(admin);
        log.info("[compatibility] rotated to version={}, states={}",
                newVersion, keyStore.allVersions().stream()
                        .map(k -> "v" + k.version() + ":" + k.state()).toList());
        assertEquals(2, newVersion);

        byte[] newPlaintext = "sealed under v2".getBytes(StandardCharsets.UTF_8);
        byte[] newCiphertext = cipherService.encrypt(allInOne, newPlaintext);
        assertEquals(2, EnvelopeCiphertext.decode(newCiphertext).keyVersion());

        byte[] legacyRecovered = cipherService.decrypt(allInOne, legacyCiphertext);
        byte[] newRecovered = cipherService.decrypt(allInOne, newCiphertext);
        log.info("[compatibility] decision: v1->'{}', v2->'{}' both decryptable",
                new String(legacyRecovered, StandardCharsets.UTF_8),
                new String(newRecovered, StandardCharsets.UTF_8));
        assertArrayEquals(legacyPlaintext, legacyRecovered);
        assertArrayEquals(newPlaintext, newRecovered);
    }

    @Test
    void decryptWithUnknownVersionIsRejected() {
        byte[] ciphertext = cipherService.encrypt(allInOne, "x".getBytes(StandardCharsets.UTF_8));
        EnvelopeCiphertext parsed = EnvelopeCiphertext.decode(ciphertext);
        byte[] reencoded = new EnvelopeCiphertext(
                999, parsed.wrappedDek(), parsed.nonce(), parsed.payload()).encode();

        log.info("[unknown-version] input claims keyVersion=999, knownVersions={}",
                keyStore.allVersions().stream().map(k -> k.version()).toList());
        UnknownKeyVersionException ex = assertThrows(UnknownKeyVersionException.class,
                () -> cipherService.decrypt(allInOne, reencoded));
        log.info("[unknown-version] decision: rejected with reason='{}'", ex.getMessage());
        assertEquals(999, ex.requestedVersion());
    }

    @Test
    void ciphertextTamperingIsRejectedAndExplained() {
        byte[] ciphertext = cipherService.encrypt(allInOne, "integrity".getBytes(StandardCharsets.UTF_8));
        byte[] tampered = ciphertext.clone();
        // 翻转密文靠后位置的一个字节（落在 GCM 密文/标签区）
        int pos = tampered.length - 5;
        tampered[pos] ^= 0x01;
        log.info("[tamper] flipped byte at offset {}: {} -> {}",
                pos, HexFormat.of().formatHex(new byte[]{ciphertext[pos]}),
                HexFormat.of().formatHex(new byte[]{tampered[pos]}));

        CiphertextTamperedException ex = assertThrows(CiphertextTamperedException.class,
                () -> cipherService.decrypt(allInOne, tampered));
        log.info("[tamper] decision: rejected with reason='{}'", ex.getMessage());
        assertTrue(ex.getMessage().contains("authentication failed"));
    }

    @Test
    void wrongKeyIsRejectedAsAuthenticationFailure() {
        // v1 加密后强制轮换到一个“外来”密钥库：同版本号但材料不同
        byte[] ciphertext = cipherService.encrypt(allInOne, "foreign".getBytes(StandardCharsets.UTF_8));
        InMemoryKeyStore foreignStore = new InMemoryKeyStore(
                "ffffffffffffffffffffffffffffffff".getBytes(StandardCharsets.UTF_8), 1);
        EnvelopeCipherService foreignService = new EnvelopeCipherService(
                foreignStore,
                new com.github.highcumontoa.envelopekeyrotationjava.crypto
                        .SecureRandomNonceGenerator(),
                auditLog);

        log.info("[wrong-key] v1 ciphertext presented to a store whose v1 key differs");
        CiphertextTamperedException ex = assertThrows(CiphertextTamperedException.class,
                () -> foreignService.decrypt(allInOne, ciphertext));
        log.info("[wrong-key] decision: rejected with reason='{}'", ex.getMessage());
        assertTrue(ex.getMessage().contains("key mismatch"));
    }

    @Test
    void malformedEnvelopeIsRejected() {
        byte[] garbage = "this-is-not-an-envelope".getBytes(StandardCharsets.UTF_8);
        log.info("[malformed] input {} bytes, magic check expected to fail", garbage.length);
        CiphertextTamperedException ex = assertThrows(CiphertextTamperedException.class,
                () -> cipherService.decrypt(allInOne, garbage));
        log.info("[malformed] decision: rejected with reason='{}'", ex.getMessage());
        assertTrue(ex.getMessage().contains("bad magic"));
    }

    @Test
    void missingRolesAreDenied() {
        log.info("[authz] encryptor-only calls decrypt; decryptor-only calls encrypt");
        AccessDeniedException decryptDenied = assertThrows(AccessDeniedException.class,
                () -> cipherService.decrypt(encryptor, new byte[16]));
        AccessDeniedException encryptDenied = assertThrows(AccessDeniedException.class,
                () -> cipherService.encrypt(decryptor, "z".getBytes(StandardCharsets.UTF_8)));
        log.info("[authz] decision: decrypt->'{}', encrypt->'{}'",
                decryptDenied.getMessage(), encryptDenied.getMessage());
        assertEquals(Role.DECRYPTOR.name(), decryptDenied.requiredRole());
        assertEquals(Role.ENCRYPTOR.name(), encryptDenied.requiredRole());
    }

    @Test
    void nonceReuseIsRejectedAndAudited() {
        byte[] fixed = new byte[12];
        Arrays.fill(fixed, (byte) 0x42);
        NonceGenerator fixedGenerator = () -> fixed.clone();
        EnvelopeCipherService service = new EnvelopeCipherService(
                keyStore, fixedGenerator, auditLog);

        byte[] first = service.encrypt(allInOne, "first".getBytes(StandardCharsets.UTF_8));
        log.info("[nonce-reuse] first encryption used fixed nonce={}",
                HexFormat.of().formatHex(fixed));
        NonceReuseException ex = assertThrows(NonceReuseException.class,
                () -> service.encrypt(allInOne, "second".getBytes(StandardCharsets.UTF_8)));
        log.info("[nonce-reuse] decision: second encryption rejected, reason='{}'", ex.getMessage());

        // 第一次密文仍然可解
        assertArrayEquals("first".getBytes(StandardCharsets.UTF_8),
                cipherService.decrypt(allInOne, first));
        assertTrue(auditLog.events().stream()
                .anyMatch(e -> e.action() == AuditAction.NONCE_REUSE_REJECTED && !e.success()));
    }

    @Test
    void auditTrailContainsNoPlaintextKeyMaterial() {
        rotationService.rotate(admin);
        byte[] ciphertext = cipherService.encrypt(allInOne, "trace-me".getBytes(StandardCharsets.UTF_8));
        cipherService.decrypt(allInOne, ciphertext);

        for (AuditEvent event : auditLog.events()) {
            String blob = event.toString();
            assertNotEquals(null, blob);
            assertTrue(!blob.contains("0123456789abcdef"),
                    "audit record leaked key material: " + blob);
        }
        log.info("[audit] {} events recorded, sample: {}",
                auditLog.events().size(), auditLog.events().get(0));
    }
}
