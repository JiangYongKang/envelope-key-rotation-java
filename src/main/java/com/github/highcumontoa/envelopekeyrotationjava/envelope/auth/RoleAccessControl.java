package com.github.highcumontoa.envelopekeyrotationjava.envelope.auth;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;

/**
 * 简单角色校验：调用方必须持有所需角色，否则直接拒绝（ACCESS_DENIED）。
 * 匿名（caller 为空或无 id）同样拒绝，不进入任何密钥操作。
 */
public class RoleAccessControl implements AccessControl {

    @Override
    public void requireRole(Caller caller, Role required) {
        if (caller == null || caller.id() == null || caller.id().isBlank()) {
            throw new EnvelopeException(RejectReason.ACCESS_DENIED,
                    "anonymous caller is not permitted to perform " + required);
        }
        if (!caller.hasRole(required)) {
            throw new EnvelopeException(RejectReason.ACCESS_DENIED,
                    "caller '" + caller.id() + "' lacks required role " + required);
        }
    }
}
