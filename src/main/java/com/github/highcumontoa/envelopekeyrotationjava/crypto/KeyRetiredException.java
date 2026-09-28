package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 试图使用已停用(RETIRED)的密钥版本执行加密。
 */
public class KeyRetiredException extends CryptoOperationException {

    private final int version;

    public KeyRetiredException(int version) {
        super("key version retired, encryption not allowed: " + version);
        this.version = version;
    }

    public int version() {
        return version;
    }
}
