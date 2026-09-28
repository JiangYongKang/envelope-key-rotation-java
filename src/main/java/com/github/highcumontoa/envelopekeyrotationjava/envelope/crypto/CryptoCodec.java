package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

/**
 * AES-GCM 原语封装：屏蔽底层加密库，所有底层异常在实现内归类。
 */
public interface CryptoCodec {
    byte[] seal(byte[] key, byte[] nonce, byte[] plaintext);
    byte[] open(byte[] key, byte[] nonce, byte[] ciphertextWithTag);
}
