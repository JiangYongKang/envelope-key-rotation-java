package com.github.highcumontoa.envelopekeyrotationjava.audit;

/**
 * 需要留痕的敏感操作类型。
 */
public enum AuditAction {
    KEY_ROTATED,
    ENCRYPT,
    ENCRYPT_DENIED,
    DECRYPT_SUCCEEDED,
    DECRYPT_FAILED,
    DECRYPT_DENIED,
    ROTATE_DENIED,
    NONCE_REUSE_REJECTED
}
