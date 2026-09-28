package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import java.util.List;
import java.util.Optional;

/**
 * 本地密钥版本库。所有方法实现需保证线程安全；
 * 轮换过程中新旧版本必须共存。
 */
public interface KeyStore {

    /** 当前用于加密的 ACTIVE 密钥版本。 */
    Optional<ManagedKey> currentKey();

    /** 按版本号查找密钥（ACTIVE 与 RETIRED 均可查到）。 */
    Optional<ManagedKey> findByVersion(int version);

    /** 全部密钥版本，按版本号升序。 */
    List<ManagedKey> allVersions();

    /**
     * 原子轮换：把当前 ACTIVE 版本置为 RETIRED，并装入新的 ACTIVE 版本。
     *
     * @return 轮换后新的当前版本
     */
    ManagedKey rotate(byte[] newKeyBytes);
}
