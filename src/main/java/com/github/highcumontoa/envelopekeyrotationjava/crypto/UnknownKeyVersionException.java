package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 密文指向的密钥版本在本地密钥库中不存在。
 */
public class UnknownKeyVersionException extends CryptoOperationException {

    private final int requestedVersion;

    public UnknownKeyVersionException(int requestedVersion) {
        super("unknown key version: " + requestedVersion);
        this.requestedVersion = requestedVersion;
    }

    public int requestedVersion() {
        return requestedVersion;
    }
}
