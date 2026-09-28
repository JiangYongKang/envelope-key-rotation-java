package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import java.security.SecureRandom;

/**
 * 基于 SecureRandom 的 12 字节 nonce 生成器（AES-GCM 推荐长度）。
 */
public class SecureRandomNonceGenerator implements NonceGenerator {

    public static final int NONCE_LENGTH = 12;

    private final SecureRandom random = new SecureRandom();

    @Override
    public byte[] nextNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        return nonce;
    }
}
