package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 每次加密使用的随机数(nonce)来源。
 */
public interface NonceGenerator {

    byte[] nextNonce();
}
