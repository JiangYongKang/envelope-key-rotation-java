package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

import java.security.SecureRandom;

/**
 * 本地密钥材料来源：仅使用本地 {@link SecureRandom} 产生 AES-256 密钥，
 * 不访问、也不依赖任何外部 KMS 或网络服务。
 */
public class LocalKeyMaterialProviderImpl implements LocalKeyMaterialProvider {

    public static final int AES_KEY_LENGTH = 32; // AES-256

    private final SecureRandom secureRandom;

    public LocalKeyMaterialProviderImpl() {
        this(new SecureRandom());
    }

    public LocalKeyMaterialProviderImpl(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public byte[] generateKek() {
        return randomKey();
    }

    @Override
    public byte[] generateDek() {
        return randomKey();
    }

    private byte[] randomKey() {
        byte[] key = new byte[AES_KEY_LENGTH];
        secureRandom.nextBytes(key);
        return key;
    }
}
