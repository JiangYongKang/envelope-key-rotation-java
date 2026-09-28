package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

/**
 * 本地密钥材料来源：不依赖任何外部 KMS，只从本地（安全随机源/本地文件）产生。
 */
public interface LocalKeyMaterialProvider {
    /** 生成一个新的本地 KEK（AES-256）。 */
    byte[] generateKek();
    /** 生成一个新的本地数据密钥 DEK（AES-256，一次性）。 */
    byte[] generateDek();
}
