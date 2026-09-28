package com.github.highcumontoa.envelopekeyrotationjava.envelope.model;

import java.util.Set;

/**
 * 调用方身份与角色集合。
 */
public record Caller(String id, Set<Role> roles) {
    public boolean hasRole(Role role) {
        return roles != null && roles.contains(role);
    }
}
