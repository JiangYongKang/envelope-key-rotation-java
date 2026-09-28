package com.github.highcumontoa.envelopekeyrotationjava.envelope.error;

/**
 * 信封加密模块对外暴露的唯一业务异常类型。
 * reason 给出可区分的拒绝原因；底层加密库异常只作为 cause 保留，
 * 不直接透传其消息给调用方。
 */
public class EnvelopeException extends RuntimeException {

    private final RejectReason reason;

    public EnvelopeException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public EnvelopeException(RejectReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public RejectReason getReason() {
        return reason;
    }
}
