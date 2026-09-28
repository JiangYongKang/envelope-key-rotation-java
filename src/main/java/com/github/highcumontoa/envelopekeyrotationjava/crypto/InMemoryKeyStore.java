package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

/**
 * 进程内密钥版本库。密钥材料仅存在于本地内存，不依赖任何外部 KMS。
 * 通过单一锁保证轮换与读取的一致性与原子性：轮换时先装入新版本，
 * 再把旧版本置为 RETIRED，整个过程中新旧版本可共存、可被并发读取。
 */
public class InMemoryKeyStore implements KeyStore {

    private final Object lock = new Object();
    private final TreeMap<Integer, ManagedKey> versions = new TreeMap<>();
    private int currentVersion;

    public InMemoryKeyStore(byte[] initialKey, int initialVersion) {
        if (initialKey == null || initialKey.length == 0) {
            throw new IllegalArgumentException("initial key material is required");
        }
        ManagedKey initial = new ManagedKey(
                initialVersion, KeyState.ACTIVE, initialKey.clone(), Instant.now());
        versions.put(initialVersion, initial);
        this.currentVersion = initialVersion;
    }

    @Override
    public Optional<ManagedKey> currentKey() {
        synchronized (lock) {
            return Optional.of(copy(versions.get(currentVersion)));
        }
    }

    @Override
    public Optional<ManagedKey> findByVersion(int version) {
        synchronized (lock) {
            ManagedKey key = versions.get(version);
            return Optional.ofNullable(key == null ? null : copy(key));
        }
    }

    @Override
    public List<ManagedKey> allVersions() {
        synchronized (lock) {
            List<ManagedKey> all = new ArrayList<>(versions.size());
            for (ManagedKey key : versions.values()) {
                all.add(copy(key));
            }
            return List.copyOf(all);
        }
    }

    @Override
    public ManagedKey rotate(byte[] newKeyBytes) {
        if (newKeyBytes == null || newKeyBytes.length == 0) {
            throw new IllegalArgumentException("new key material is required");
        }
        synchronized (lock) {
            ManagedKey old = versions.get(currentVersion);
            // 新版本号严格递增，先放入新版本，再停用旧版本，保证共存窗口。
            int newVersion = currentVersion + 1;
            ManagedKey fresh = new ManagedKey(
                    newVersion, KeyState.ACTIVE, newKeyBytes.clone(), Instant.now());
            versions.put(newVersion, fresh);
            currentVersion = newVersion;
            if (old != null) {
                versions.put(old.version(), old.withState(KeyState.RETIRED));
            }
            return copy(fresh);
        }
    }

    private static ManagedKey copy(ManagedKey key) {
        return new ManagedKey(key.version(), key.state(), key.keyBytes().clone(), key.createdAt());
    }
}
