package com.github.highcumontoa.envelopekeyrotationjava.security;

/**
 * 调用方角色。
 */
public enum Role {
    /** 允许执行加密。 */
    ENCRYPTOR,
    /** 允许执行解密。 */
    DECRYPTOR,
    /** 允许执行密钥轮换。 */
    KEY_ADMIN
}
