package com.github.highcumontoa.envelopekeyrotationjava.security;

import java.util.Set;

/**
 * 调用方身份及其角色集合。
 */
public record Caller(String id, Set<Role> roles) {

    public boolean hasRole(Role role) {
        return roles != null && roles.contains(role);
    }
}
