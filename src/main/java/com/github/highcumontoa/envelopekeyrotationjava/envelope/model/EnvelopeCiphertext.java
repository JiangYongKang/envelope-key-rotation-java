package com.github.highcumontoa.envelopekeyrotationjava.envelope.model;

/**
 * 信封密文值对象：密文可序列化回写，每条都带加密时的 KEK 版本号。
 *
 * @param kekVersion  包装 DEK 使用的 KEK 版本
 * @param wrappedDek  KEK-GCM 加密后的 DEK 密文（含 GCM 认证标签）
 * @param dekNonce    包装 DEK 使用的 nonce
 * @param dataCipher  DEK-GCM 加密后的业务数据密文（含 GCM 认证标签）
 * @param dataNonce   加密业务数据使用的 nonce
 */
public record EnvelopeCiphertext(
        int kekVersion,
        byte[] wrappedDek,
        byte[] dekNonce,
        byte[] dataCipher,
        byte[] dataNonce) {

    /** 不含任何明文材料，仅打印长度与版本，供日志判读。 */
    @Override
    public String toString() {
        return "EnvelopeCiphertext{kekVersion=" + kekVersion
                + ", wrappedDekLen=" + (wrappedDek == null ? 0 : wrappedDek.length)
                + ", dekNonceLen=" + (dekNonce == null ? 0 : dekNonce.length)
                + ", dataCipherLen=" + (dataCipher == null ? 0 : dataCipher.length)
                + ", dataNonceLen=" + (dataNonce == null ? 0 : dataNonce.length) + "}";
    }
}
