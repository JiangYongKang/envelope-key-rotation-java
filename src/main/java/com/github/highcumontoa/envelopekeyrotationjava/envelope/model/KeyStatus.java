package com.github.highcumontoa.envelopekeyrotationjava.envelope.model;

/**
 * 密钥版本生命周期状态：
 * ACTIVE   —— 当前版本，允许加解密；
 * DISABLED —— 已停用版本，仅允许解密（读取历史密文），不允许再加密；
 * 轮换采用“新版本激活 + 旧版本置为 DISABLED”的方式，旧版本不删除以保证历史密文可解。
 */
public enum KeyStatus {
    ACTIVE,
    DISABLED
}
