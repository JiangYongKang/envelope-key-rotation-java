package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

/** 本地安全随机数 nonce 生成器（GCM 推荐 96 bit）。 */
public interface NonceGenerator {
    byte[] generate();
}
