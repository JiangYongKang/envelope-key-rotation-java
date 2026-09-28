package com.github.highcumontoa.envelopekeyrotationjava.envelope.error;

/**
 * 可区分的拒绝原因。任何底层加密库异常都必须先归类为本枚举，
 * 不允许直接透出给调用方。
 */
public enum RejectReason {
    VERSION_NOT_FOUND,
    KEY_DISABLED_FOR_ENCRYPT,
    CIPHERTEXT_MALFORMED,
    AUTH_TAG_MISMATCH,
    NONCE_REUSE_DETECTED,
    NONCE_GENERATION_FAILED,
    ROTATION_CONFLICT,
    ACCESS_DENIED,
    INVALID_ARGUMENT,
    INTERNAL_CRYPTO_ERROR
}
