package com.github.highcumontoa.envelopekeyrotationjava.security;

/**
 * 调用方缺少执行敏感操作所需角色。
 */
public class AccessDeniedException extends RuntimeException {

    private final String callerId;
    private final String requiredRole;

    public AccessDeniedException(String callerId, String requiredRole) {
        super("access denied");
        this.callerId = callerId;
        this.requiredRole = requiredRole;
    }

    public String callerId() {
        return callerId;
    }

    public String requiredRole() {
        return requiredRole;
    }
}
