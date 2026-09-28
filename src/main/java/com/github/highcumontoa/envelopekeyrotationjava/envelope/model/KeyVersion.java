package com.github.highcumontoa.envelopekeyrotationjava.envelope.model;

import java.time.Instant;

/**
 * 一个密钥版本。KEK（密钥加密密钥）用于信封包装 DEK。
 * 本类绝不允许被审计日志打印密钥材料：toString 已做脱敏。
 */
public final class KeyVersion {

    private final int version;
    private final KeyStatus status;
    private final byte[] kek;
    private final Instant createdAt;

    public KeyVersion(int version, KeyStatus status, byte[] kek, Instant createdAt) {
        this.version = version;
        this.status = status;
        this.kek = kek == null ? null : kek.clone();
        this.createdAt = createdAt;
    }

    public int getVersion() {
        return version;
    }

    public KeyStatus getStatus() {
        return status;
    }

    public byte[] getKek() {
        return kek == null ? null : kek.clone();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /** 仅暴露元数据，绝不包含密钥材料。 */
    @Override
    public String toString() {
        return "KeyVersion{version=" + version + ", status=" + status
                + ", kekLength=" + (kek == null ? 0 : kek.length)
                + ", createdAt=" + createdAt + "}";
    }
}
