package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

import java.security.SecureRandom;

/**
 * 本地 {@link SecureRandom} 生成 GCM 推荐的 96 bit（12 字节）nonce。
 * 不依赖任何外部随机源。
 */
public class SecureRandomNonceGenerator implements NonceGenerator {

    public static final int GCM_IV_LENGTH = 12;

    private final SecureRandom secureRandom;

    public SecureRandomNonceGenerator() {
        this(new SecureRandom());
    }

    public SecureRandomNonceGenerator(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public byte[] generate() {
        byte[] nonce = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(nonce);
        return nonce;
    }
}
