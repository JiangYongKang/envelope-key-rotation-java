package com.github.highcumontoa.envelopekeyrotationjava.envelope.model;

/**
 * 调用方角色：
 * ENCRYPTOR —— 仅可使用当前版本加密；
 * DECRYPTOR —— 可解密任意现存版本的密文；
 * ROTATOR   —— 可触发密钥轮换。
 */
public enum Role {
    ENCRYPTOR,
    DECRYPTOR,
    ROTATOR
}
