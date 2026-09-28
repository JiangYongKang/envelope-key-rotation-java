package com.github.highcumontoa.envelopekeyrotationjava.envelope.model;

import java.time.Instant;

/**
 * 审计留痕事件。任何字段都不得包含明文密钥材料或明文业务数据。
 *
 * @param timestamp  事件时间
 * @param caller     调用方标识
 * @param action     敏感动作
 * @param success    是否成功
 * @param keyVersion 涉及的密钥版本（可为空，例如解析失败尚无版本）
 * @param reason     失败时的拒绝原因名称（成功为 null）
 * @param detail     脱敏后的附加判定依据（只含长度/版本等元数据）
 */
public record AuditEvent(
        Instant timestamp,
        String caller,
        AuditAction action,
        boolean success,
        Integer keyVersion,
        String reason,
        String detail) {
}
