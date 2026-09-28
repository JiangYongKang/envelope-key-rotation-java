package com.github.highcumontoa.envelopekeyrotationjava.security;

/**
 * 角色鉴权：调用方缺少所需角色时抛 AccessDeniedException，直接拒绝。
 */
public class PermissionChecker {

    public void requireRole(Caller caller, Role required) {
        if (caller == null || caller.id() == null || caller.id().isBlank()) {
            throw new AccessDeniedException("<anonymous>", required.name());
        }
        if (!caller.hasRole(required)) {
            throw new AccessDeniedException(caller.id(), required.name());
        }
    }
}
