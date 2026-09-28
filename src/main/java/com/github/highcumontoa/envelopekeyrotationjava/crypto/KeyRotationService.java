package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditAction;
import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.security.AccessDeniedException;
import com.github.highcumontoa.envelopekeyrotationjava.security.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.security.PermissionChecker;
import com.github.highcumontoa.envelopekeyrotationjava.security.Role;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;

/**
 * 密钥轮换服务：在本地用 SecureRandom 生成全新 256 位 KEK，
 * 原子替换当前版本；旧版本转为 RETIRED 保留以供历史密文解密。
 * 仅 KEY_ADMIN 角色可执行，每次轮换留痕。
 */
public class KeyRotationService {

    public static final int KEY_LENGTH_BYTES = 32;

    private final KeyStore keyStore;
    private final AuditLog auditLog;
    private final PermissionChecker permissionChecker;
    private final SecureRandom random = new SecureRandom();

    public KeyRotationService(KeyStore keyStore, AuditLog auditLog) {
        this(keyStore, auditLog, new PermissionChecker());
    }

    public KeyRotationService(KeyStore keyStore, AuditLog auditLog,
                              PermissionChecker permissionChecker) {
        this.keyStore = keyStore;
        this.auditLog = auditLog;
        this.permissionChecker = permissionChecker;
    }

    public int rotate(Caller caller) {
        try {
            permissionChecker.requireRole(caller, Role.KEY_ADMIN);
        } catch (AccessDeniedException denied) {
            auditLog.record(new AuditEvent(Instant.now(), AuditAction.ROTATE_DENIED,
                    caller == null ? "<unknown>" : caller.id(), "-", false,
                    "missing role " + Role.KEY_ADMIN));
            throw denied;
        }

        Integer previousVersion = keyStore.currentKey().map(ManagedKey::version).orElse(null);
        byte[] freshKey = new byte[KEY_LENGTH_BYTES];
        try {
            random.nextBytes(freshKey);
            ManagedKey rotated = keyStore.rotate(freshKey);
            auditLog.record(new AuditEvent(
                    Instant.now(), AuditAction.KEY_ROTATED, caller.id(),
                    String.valueOf(rotated.version()), true,
                    "previousVersion=" + (previousVersion == null ? "-" : previousVersion)
                            + ", retainedVersions=" + keyStore.allVersions().size()
                            + ", keyMaterial=***redacted***"));
            return rotated.version();
        } finally {
            Arrays.fill(freshKey, (byte) 0);
        }
    }
}
