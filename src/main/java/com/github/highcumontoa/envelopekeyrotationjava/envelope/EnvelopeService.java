package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyVersion;

import java.util.List;

/**
 * 信封加密、解密与密钥轮换的应用服务（门面）。
 */
public interface EnvelopeService {

    /** 使用当前 ACTIVE 版本 KEK 进行信封加密，返回自描述二进制密文。 */
    byte[] encrypt(Caller caller, byte[] plaintext);

    /** 按密文中记录的版本取 KEK 解密；历史版本同样可解。 */
    byte[] decrypt(Caller caller, byte[] encodedCiphertext);

    /** 轮换：生成新版本并停用旧版本。 */
    int rotate(Caller caller);

    /** 查看现存版本元数据（不含密钥材料）。 */
    List<KeyVersion> versions();
}
