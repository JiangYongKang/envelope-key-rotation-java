package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

/**
 * 同一 KEK 版本下的 nonce 复用检测器。
 */
public interface NonceTracker {
    /** 首次使用返回 true；检测到该版本下 nonce 复用返回 false。 */
    boolean registerIfAbsent(int keyVersion, byte[] nonce);
}
