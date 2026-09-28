package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 信封加解密领域异常基类。
 * 只携带可对外解释的拒绝原因，不包装/透传底层加密库异常。
 */
public class CryptoOperationException extends RuntimeException {

    public CryptoOperationException(String message) {
        super(message);
    }
}
