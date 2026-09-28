package com.github.highcumontoa.envelopekeyrotationjava.envelope.store;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProvider;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyStatus;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyVersion;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

/**
 * 本地内存密钥库。
 *
 * 生命周期规则：
 * - 进程启动时自动生成版本 1（ACTIVE），保证总有可加密版本；
 * - 轮换：新版本号 = 最大版本号 + 1 且置 ACTIVE，旧 ACTIVE 版本置 DISABLED；
 * - DISABLED 版本保留不删除，仅用于解密历史密文；
 * - rotate 在同一把锁内完成“读现状-生成-改状态”，并发轮换串行化，
 *   不会出现两个线程同时得到同一个“新版本号”或两个 ACTIVE 并存。
 *
 * 返回的 {@link KeyVersion} 自身对密钥材料做防御性拷贝。
 */
public class InMemoryKeyStore implements KeyStore {

    private final LocalKeyMaterialProvider materialProvider;
    private final Object rotationLock = new Object();
    // TreeMap 保证版本号有序；所有访问都在 synchronized(rotationLock) 内
    private final TreeMap<Integer, KeyVersion> versions = new TreeMap<>();

    public InMemoryKeyStore(LocalKeyMaterialProvider materialProvider) {
        this.materialProvider = materialProvider;
        synchronized (rotationLock) {
            versions.put(1, new KeyVersion(1, KeyStatus.ACTIVE,
                    materialProvider.generateKek(), Instant.now()));
        }
    }

    @Override
    public KeyVersion rotate() {
        synchronized (rotationLock) {
            int nextVersion = versions.lastKey() + 1;
            // 先把现有 ACTIVE 版本全部停用（正常只有一个）
            List<KeyVersion> snapshot = new ArrayList<>(versions.values());
            for (KeyVersion kv : snapshot) {
                if (kv.getStatus() == KeyStatus.ACTIVE) {
                    versions.put(kv.getVersion(), new KeyVersion(
                            kv.getVersion(), KeyStatus.DISABLED,
                            kv.getKek(), kv.getCreatedAt()));
                }
            }
            KeyVersion created = new KeyVersion(nextVersion, KeyStatus.ACTIVE,
                    materialProvider.generateKek(), Instant.now());
            versions.put(nextVersion, created);
            return created;
        }
    }

    @Override
    public Optional<KeyVersion> findVersion(int version) {
        synchronized (rotationLock) {
            return Optional.ofNullable(versions.get(version));
        }
    }

    @Override
    public Optional<KeyVersion> currentVersion() {
        synchronized (rotationLock) {
            return versions.values().stream()
                    .filter(kv -> kv.getStatus() == KeyStatus.ACTIVE)
                    .max(java.util.Comparator.comparingInt(KeyVersion::getVersion));
        }
    }

    @Override
    public List<KeyVersion> allVersions() {
        synchronized (rotationLock) {
            return List.copyOf(versions.values());
        }
    }
}
