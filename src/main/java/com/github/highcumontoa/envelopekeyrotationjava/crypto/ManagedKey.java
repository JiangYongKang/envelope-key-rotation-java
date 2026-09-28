package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import java.time.Instant;

/**
 * 受管密钥版本。密钥材料(keyBytes)为敏感字段，
 * 不允许出现在审计记录、异常消息或日志中。
 */
public record ManagedKey(int version,
                         KeyState state,
                         byte[] keyBytes,
                         Instant createdAt) {

    public ManagedKey withState(KeyState newState) {
        return new ManagedKey(version, newState, keyBytes, createdAt);
    }
}
