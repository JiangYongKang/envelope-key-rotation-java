package com.github.highcumontoa.envelopekeyrotationjava.crypto;

/**
 * 密钥生命周期状态。
 * ACTIVE   —— 当前版本，可加密、可解密；
 * RETIRED  —— 已被轮换的历史版本，只能解密，不能再加密。
 */
public enum KeyState {
    ACTIVE,
    RETIRED
}
