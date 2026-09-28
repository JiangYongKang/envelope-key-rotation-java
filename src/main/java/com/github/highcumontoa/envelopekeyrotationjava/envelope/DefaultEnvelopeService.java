package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.auth.AccessControl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CiphertextFormat;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CryptoCodec;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProvider;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.NonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.NonceTracker;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.EnvelopeCiphertext;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyStatus;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyVersion;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.KeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * 本地信封加密门面默认实现。
 *
 * 信封结构：DEK（一次性 AES-256）加密业务数据；KEK（按版本管理的主密钥）
 * 以 AES-GCM 包装 DEK。密文自带 KEK 版本号。
 *
 * 拒绝路径全部归类为 {@link EnvelopeException} + {@link RejectReason}，
 * 底层加密库异常不会透出。
 */
public class DefaultEnvelopeService implements EnvelopeService {

    private static final Logger log = LoggerFactory.getLogger(DefaultEnvelopeService.class);

    private final KeyStore keyStore;
    private final CryptoCodec cryptoCodec;
    private final NonceGenerator nonceGenerator;
    private final NonceTracker nonceTracker;
    private final LocalKeyMaterialProvider materialProvider;
    private final AccessControl accessControl;
    private final AuditLog auditLog;
    private final CiphertextFormat ciphertextFormat;

    public DefaultEnvelopeService(KeyStore keyStore,
                                  CryptoCodec cryptoCodec,
                                  NonceGenerator nonceGenerator,
                                  NonceTracker nonceTracker,
                                  LocalKeyMaterialProvider materialProvider,
                                  AccessControl accessControl,
                                  AuditLog auditLog,
                                  CiphertextFormat ciphertextFormat) {
        this.keyStore = keyStore;
        this.cryptoCodec = cryptoCodec;
        this.nonceGenerator = nonceGenerator;
        this.nonceTracker = nonceTracker;
        this.materialProvider = materialProvider;
        this.accessControl = accessControl;
        this.auditLog = auditLog;
        this.ciphertextFormat = ciphertextFormat;
    }

    @Override
    public byte[] encrypt(Caller caller, byte[] plaintext) {
        if (plaintext == null) {
            throw new EnvelopeException(RejectReason.INVALID_ARGUMENT, "plaintext is null");
        }
        authorize(caller, AuditAction.ENCRYPT, Role.ENCRYPTOR);
        KeyVersion active = keyStore.currentVersion()
                .orElseThrow(() -> new EnvelopeException(RejectReason.VERSION_NOT_FOUND,
                        "no ACTIVE key version available for encryption"));
        if (active.getStatus() != KeyStatus.ACTIVE) {
            // 双保险：已停用密钥只能解密，不能再加密
            throw deny(caller, AuditAction.ENCRYPT, active.getVersion(),
                    RejectReason.KEY_DISABLED_FOR_ENCRYPT,
                    "encryption attempted with non-ACTIVE key version " + active.getVersion());
        }

        // 1) 一次性 DEK + 数据 nonce
        byte[] dek = materialProvider.generateDek();
        byte[] dataNonce = nonceGenerator.generate();
        // 2) KEK 包装 nonce：先做复用登记，复用必须拒绝而不是照常加密
        byte[] wrapNonce = nonceGenerator.generate();
        if (!nonceTracker.registerIfAbsent(active.getVersion(), wrapNonce)) {
            throw deny(caller, AuditAction.ENCRYPT, active.getVersion(),
                    RejectReason.NONCE_REUSE_DETECTED,
                    "wrap nonce reused under key version " + active.getVersion());
        }

        byte[] encoded;
        try {
            byte[] dataCipher = cryptoCodec.seal(dek, dataNonce, plaintext);
            byte[] wrappedDek = cryptoCodec.seal(active.getKek(), wrapNonce, dek);
            encoded = ciphertextFormat.encode(new EnvelopeCiphertext(
                    active.getVersion(), wrappedDek, wrapNonce, dataCipher, dataNonce));
        } catch (EnvelopeException e) {
            throw deny(caller, AuditAction.ENCRYPT, active.getVersion(),
                    e.getReason(), "encryption rejected: " + e.getMessage());
        } finally {
            // 不把 DEK 留在栈上对象之外
            java.util.Arrays.fill(dek, (byte) 0);
        }

        log.info("[ENCRYPT] caller={} plaintextLen={} keyVersion={} ciphertextLen={} decision=ALLOW",
                caller.id(), plaintext.length, active.getVersion(), encoded.length);
        auditLog.record(caller, AuditAction.ENCRYPT, true, active.getVersion(), null,
                "plaintextLen=" + plaintext.length + ", ciphertextLen=" + encoded.length);
        return encoded;
    }

    @Override
    public byte[] decrypt(Caller caller, byte[] encodedCiphertext) {
        authorize(caller, AuditAction.DECRYPT, Role.DECRYPTOR);
        if (encodedCiphertext == null || encodedCiphertext.length == 0) {
            throw new EnvelopeException(RejectReason.INVALID_ARGUMENT,
                    "ciphertext bytes are null or empty");
        }
        // 先解析格式；篡改导致解析失败时还没有版本号
        EnvelopeCiphertext ciphertext;
        try {
            ciphertext = ciphertextFormat.decode(encodedCiphertext);
        } catch (EnvelopeException e) {
            throw deny(caller, AuditAction.DECRYPT, null,
                    e.getReason(), "decode rejected: " + e.getMessage());
        }

        int version = ciphertext.kekVersion();
        KeyVersion kv = keyStore.findVersion(version)
                .orElseThrow(() -> deny(caller, AuditAction.DECRYPT, version,
                        RejectReason.VERSION_NOT_FOUND,
                        "key version " + version + " referenced by ciphertext does not exist"));

        // DISABLED 版本允许解密（读取历史密文），这里不按状态拒绝
        byte[] plaintext;
        try {
            byte[] dek = cryptoCodec.open(kv.getKek(), ciphertext.dekNonce(),
                    ciphertext.wrappedDek());
            try {
                plaintext = cryptoCodec.open(dek, ciphertext.dataNonce(),
                        ciphertext.dataCipher());
            } finally {
                java.util.Arrays.fill(dek, (byte) 0);
            }
        } catch (EnvelopeException e) {
            // AUTH_TAG_MISMATCH：密钥对不上/密文被篡改，二者在 GCM 下不可进一步区分
            throw deny(caller, AuditAction.DECRYPT, version,
                    e.getReason(), "decrypt rejected for version " + version
                            + ": " + e.getMessage());
        }

        log.info("[DECRYPT] caller={} keyVersion={} keyStatus={} ciphertextLen={} plaintextLen={} decision=ALLOW",
                caller.id(), version, kv.getStatus(), encodedCiphertext.length, plaintext.length);
        auditLog.record(caller, AuditAction.DECRYPT, true, version, null,
                "keyStatus=" + kv.getStatus() + ", ciphertextLen=" + encodedCiphertext.length
                        + ", plaintextLen=" + plaintext.length);
        return plaintext;
    }

    @Override
    public int rotate(Caller caller) {
        authorize(caller, AuditAction.KEY_ROTATE, Role.ROTATOR);
        try {
            KeyVersion created = keyStore.rotate();
            log.info("[ROTATE] caller={} newKeyVersion={} decision=ALLOW (previous versions retained for decrypt)",
                    caller.id(), created.getVersion());
            auditLog.record(caller, AuditAction.KEY_ROTATE, true, created.getVersion(), null,
                    "new ACTIVE version created; older versions marked DISABLED");
            return created.getVersion();
        } catch (RuntimeException e) {
            throw deny(caller, AuditAction.KEY_ROTATE, null,
                    RejectReason.ROTATION_CONFLICT, "rotation failed: " + e.getClass().getSimpleName());
        }
    }

    @Override
    public List<KeyVersion> versions() {
        return keyStore.allVersions();
    }

    /** 权限校验：越权/匿名统一记录 ACCESS_DENIED 留痕后拒绝。 */
    private void authorize(Caller caller, AuditAction action, Role required) {
        try {
            accessControl.requireRole(caller, required);
        } catch (EnvelopeException e) {
            String callerId = caller == null ? "anonymous" : caller.id();
            log.info("[DENY] caller={} action={} keyVersion=null reason={} basis={}",
                    callerId, action, e.getReason(), e.getMessage());
            auditLog.record(caller, AuditAction.ACCESS_DENIED, false, null,
                    e.getReason().name(), "required role " + required);
            throw e;
        }
    }

    /** 记录一条拒绝留痕并抛出可解释异常；detail 只允许元数据。 */
    private EnvelopeException deny(Caller caller, AuditAction action, Integer version,
                                   RejectReason reason, String detail) {
        String callerId = caller == null ? "anonymous" : caller.id();
        log.info("[DENY] caller={} action={} keyVersion={} reason={} basis={}",
                callerId, action, version, reason, detail);
        auditLog.record(caller, action, false, version, reason.name(), detail);
        return new EnvelopeException(reason, detail);
    }
}
