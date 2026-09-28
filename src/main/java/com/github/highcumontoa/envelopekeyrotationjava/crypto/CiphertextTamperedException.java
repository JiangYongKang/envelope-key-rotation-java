package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 密文格式非法，或认证标签校验失败（密钥不匹配 / 密文被篡改）。
 * 底层 AEAD 失败细节不外泄，统一归为该可解释原因。
 */
public class CiphertextTamperedException extends CryptoOperationException {

    public CiphertextTamperedException(String reason) {
        super("ciphertext rejected: " + reason);
    }
}
