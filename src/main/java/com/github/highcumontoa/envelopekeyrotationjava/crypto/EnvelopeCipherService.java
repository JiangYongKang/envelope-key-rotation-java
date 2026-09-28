package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.security.AccessDeniedException;
import com.github.highcumontoa.envelopekeyrotationjava.security.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.security.PermissionChecker;
import com.github.highcumontoa.envelopekeyrotationjava.security.Role;

import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 信封加密/解密服务。
 *
 * 加密时随机生成一次性数据密钥 DEK（32 字节）：
 *   - 用当前 ACTIVE 的 KEK 版本，AES-GCM 包装 DEK；
 *     wrappedDek 字段布局为 kekNonce(12) || GCM(DEK, aad=版本绑定)；
 *   - 用 DEK，AES-GCM 加密明文，nonce 字段为数据 nonce，
 *     payload 内含 GCM 认证标签；
 *   - 密文自描述携带 KEK 版本号，解密时按版本取对应密钥，
 *     ACTIVE 与 RETIRED 版本均可解密。
 *
 * 安全约定：
 *   - 同一 KEK 版本下出现包装 nonce 复用立即拒绝（NonceReuseException）；
 *   - DEK 每条消息一次性随机生成、用后清零，数据 nonce 无需跨消息追踪；
 *   - AAD 绑定魔数与 KEK 版本，防止密文被搬到其他版本下解密；
 *   - 底层加密库异常一律转换为可解释的领域异常，不直接透出。
 */
public class EnvelopeCipherService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BITS = 128;
    private static final int DEK_LENGTH_BYTES = 32;
    private static final int KEK_NONCE_LENGTH = SecureRandomNonceGenerator.NONCE_LENGTH;
    private static final int DATA_NONCE_LENGTH = 12;
    private static final byte[] AAD_MAGIC = {'E', 'N', 'V', '1', 'A', 'A', 'D'};

    private final KeyStore keyStore;
    private final NonceGenerator nonceGenerator;
    private final AuditLog auditLog;
    private final PermissionChecker permissionChecker;
    private final SecureRandom random = new SecureRandom();

    /** keyVersion -> 已用于包装 DEK 的 KEK nonce 集合（十六进制）。 */
    private final ConcurrentHashMap<Integer, Set<String>> usedKekNonces = new ConcurrentHashMap<>();

    public EnvelopeCipherService(KeyStore keyStore,
                                 NonceGenerator nonceGenerator,
                                 AuditLog auditLog) {
        this(keyStore, nonceGenerator, auditLog, new PermissionChecker());
    }

    public EnvelopeCipherService(KeyStore keyStore,
                                 NonceGenerator nonceGenerator,
                                 AuditLog auditLog,
                                 PermissionChecker permissionChecker) {
        this.keyStore = keyStore;
        this.nonceGenerator = nonceGenerator;
        this.auditLog = auditLog;
        this.permissionChecker = permissionChecker;
    }

    public byte[] encrypt(Caller caller, byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext is required");
        }
        try {
            permissionChecker.requireRole(caller, Role.ENCRYPTOR);
        } catch (AccessDeniedException denied) {
            audit(AuditAction.ENCRYPT_DENIED, caller, null, false,
                    "missing role " + Role.ENCRYPTOR);
            throw denied;
        }

        ManagedKey kek = keyStore.currentKey()
                .orElseThrow(() -> new CryptoOperationException("no active key available"));
        if (kek.state() != KeyState.ACTIVE) {
            throw new KeyRetiredException(kek.version());
        }

        byte[] kekNonce = nonceGenerator.nextNonce();
        if (!reserveNonce(kek.version(), kekNonce)) {
            audit(AuditAction.NONCE_REUSE_REJECTED, caller, kek.version(), false,
                    "kek nonce already used under this version, encryption rejected");
            throw new NonceReuseException(kek.version());
        }

        byte[] dek = new byte[DEK_LENGTH_BYTES];
        random.nextBytes(dek);
        byte[] dataNonce = new byte[DATA_NONCE_LENGTH];
        random.nextBytes(dataNonce);

        try {
            byte[] aad = aadFor(kek.version());
            byte[] wrappedDekCipher = aeadEncrypt(kek.keyBytes(), kekNonce, dek, aad);
            byte[] wrappedDek = concat(kekNonce, wrappedDekCipher);
            byte[] payload = aeadEncrypt(dek, dataNonce, plaintext, null);
            byte[] encoded = new EnvelopeCiphertext(
                    kek.version(), wrappedDek, dataNonce, payload).encode();
            audit(AuditAction.ENCRYPT, caller, kek.version(), true,
                    "plaintextBytes=" + plaintext.length
                            + ", ciphertextBytes=" + encoded.length);
            return encoded;
        } catch (GeneralSecurityException ex) {
            // 不透出底层实现细节
            throw new CryptoOperationException("encryption failed due to a local crypto error");
        } finally {
            // 密钥材料仅在方法栈内存活，不做任何落盘/日志
            Arrays.fill(dek, (byte) 0);
        }
    }

    public byte[] decrypt(Caller caller, byte[] encodedCiphertext) {
        try {
            permissionChecker.requireRole(caller, Role.DECRYPTOR);
        } catch (AccessDeniedException denied) {
            audit(AuditAction.DECRYPT_DENIED, caller, null, false,
                    "missing role " + Role.DECRYPTOR);
            throw denied;
        }

        EnvelopeCiphertext ciphertext;
        try {
            ciphertext = EnvelopeCiphertext.decode(encodedCiphertext);
        } catch (CiphertextTamperedException tampered) {
            audit(AuditAction.DECRYPT_FAILED, caller, null, false, tampered.getMessage());
            throw tampered;
        }

        ManagedKey kek = keyStore.findByVersion(ciphertext.keyVersion()).orElse(null);
        if (kek == null) {
            UnknownKeyVersionException ex =
                    new UnknownKeyVersionException(ciphertext.keyVersion());
            audit(AuditAction.DECRYPT_FAILED, caller, ciphertext.keyVersion(), false,
                    ex.getMessage());
            throw ex;
        }
        // RETIRED 版本允许解密，这里不做状态限制。

        byte[] wrappedDek = ciphertext.wrappedDek();
        if (wrappedDek.length <= KEK_NONCE_LENGTH) {
            CiphertextTamperedException ex = new CiphertextTamperedException(
                    "wrapped DEK too short (version=" + kek.version() + ")");
            audit(AuditAction.DECRYPT_FAILED, caller, kek.version(), false, ex.getMessage());
            throw ex;
        }
        byte[] kekNonce = Arrays.copyOfRange(wrappedDek, 0, KEK_NONCE_LENGTH);
        byte[] wrappedDekCipher =
                Arrays.copyOfRange(wrappedDek, KEK_NONCE_LENGTH, wrappedDek.length);

        byte[] dek = new byte[DEK_LENGTH_BYTES];
        boolean dekUnwrapped = false;
        try {
            byte[] unwrapped = aeadDecrypt(
                    kek.keyBytes(), kekNonce, wrappedDekCipher, aadFor(kek.version()));
            if (unwrapped.length != DEK_LENGTH_BYTES) {
                throw new CiphertextTamperedException(
                        "unwrapped DEK has unexpected length (version=" + kek.version() + ")");
            }
            dek = unwrapped;
            dekUnwrapped = true;
            byte[] plaintext = aeadDecrypt(
                    dek, ciphertext.nonce(), ciphertext.payload(), null);
            audit(AuditAction.DECRYPT_SUCCEEDED, caller, kek.version(), true,
                    "ciphertextBytes=" + encodedCiphertext.length
                            + ", plaintextBytes=" + plaintext.length);
            return plaintext;
        } catch (AEADBadTagException badTag) {
            CiphertextTamperedException ex = new CiphertextTamperedException(
                    "authentication failed: key mismatch or ciphertext tampered"
                            + " (version=" + kek.version() + ")");
            audit(AuditAction.DECRYPT_FAILED, caller, kek.version(), false, ex.getMessage());
            throw ex;
        } catch (CiphertextTamperedException tampered) {
            audit(AuditAction.DECRYPT_FAILED, caller, kek.version(), false,
                    tampered.getMessage());
            throw tampered;
        } catch (GeneralSecurityException other) {
            throw new CryptoOperationException("decryption failed due to a local crypto error");
        } finally {
            if (dekUnwrapped) {
                Arrays.fill(dek, (byte) 0);
            }
        }
    }

    private boolean reserveNonce(int version, byte[] nonce) {
        Set<String> used = usedKekNonces.computeIfAbsent(
                version, v -> ConcurrentHashMap.newKeySet());
        return used.add(HexFormat.of().formatHex(nonce));
    }

    private static byte[] aadFor(int keyVersion) {
        return ByteBuffer.allocate(AAD_MAGIC.length + 4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put(AAD_MAGIC)
                .putInt(keyVersion)
                .array();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] joined = new byte[first.length + second.length];
        System.arraycopy(first, 0, joined, 0, first.length);
        System.arraycopy(second, 0, joined, first.length, second.length);
        return joined;
    }

    private static byte[] aeadEncrypt(byte[] key, byte[] nonce, byte[] input, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(input);
    }

    private static byte[] aeadDecrypt(byte[] key, byte[] nonce, byte[] input, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(input);
    }

    private void audit(AuditAction action, Caller caller, Integer version,
                       boolean success, String reason) {
        String callerId = caller == null ? "<unknown>" : caller.id();
        auditLog.record(new AuditEvent(
                Instant.now(), action, callerId,
                version == null ? "-" : String.valueOf(version), success, reason));
    }
}
