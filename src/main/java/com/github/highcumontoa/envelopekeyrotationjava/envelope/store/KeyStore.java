package com.github.highcumontoa.envelopekeyrotationjava.envelope.store;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyVersion;

import java.util.List;
import java.util.Optional;

/**
 * 本地内存密钥库：保存各版本 KEK 与生命周期状态。
 * 所有读写实现需保证并发安全。
 */
public interface KeyStore {

    /** 在全局锁内执行“读取-生成新版本-停用旧版本”，避免并发轮换冲突。 */
    KeyVersion rotate();

    Optional<KeyVersion> findVersion(int version);

    /** 加解密取当前 ACTIVE 版本；不存在时返回空。 */
    Optional<KeyVersion> currentVersion();

    /** 按版本号升序返回所有版本。 */
    List<KeyVersion> allVersions();
}
