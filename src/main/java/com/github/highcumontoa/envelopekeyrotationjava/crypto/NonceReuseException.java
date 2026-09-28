package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 同一密钥版本下检测到加密随机数(nonce)被重复使用。
 * 出现即说明随机源或并发流程存在问题，必须拒绝本次加密。
 */
public class NonceReuseException extends CryptoOperationException {

    private final int version;

    public NonceReuseException(int version) {
        super("nonce reuse detected under key version: " + version);
        this.version = version;
    }

    public int version() {
        return version;
    }
}
