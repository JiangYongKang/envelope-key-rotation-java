package com.github.highcumontoa.envelopekeyrotationjava.security;

import java.util.EnumSet;
import java.util.Set;

/**
 * 从请求头解析调用方身份。
 * X-Caller-Id    调用方标识
 * X-Caller-Roles 逗号分隔的角色（ENCRYPTOR/DECRYPTOR/KEY_ADMIN）
 * 本地演示用：不接外部 IAM，无法识别的角色标记会被忽略。
 */
public class CallerResolver {

    public Caller resolve(String callerId, String rolesHeader) {
        Set<Role> roles = EnumSet.noneOf(Role.class);
        if (rolesHeader != null) {
            for (String token : rolesHeader.split(",")) {
                String trimmed = token.trim().toUpperCase();
                if (trimmed.isEmpty()) {
                    continue;
                }
                try {
                    roles.add(Role.valueOf(trimmed));
                } catch (IllegalArgumentException ignored) {
                    // 未知角色标记不授予任何权限
                }
            }
        }
        return new Caller(callerId, Set.copyOf(roles));
    }
}
