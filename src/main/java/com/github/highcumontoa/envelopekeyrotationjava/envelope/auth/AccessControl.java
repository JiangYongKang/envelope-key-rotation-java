package com.github.highcumontoa.envelopekeyrotationjava.envelope.auth;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;

/** 角色权限校验。 */
public interface AccessControl {
    void requireRole(Caller caller, Role required);
}
