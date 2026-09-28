package com.github.highcumontoa.envelopekeyrotationjava.envelope.web;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 把领域拒绝原因映射为确定的 HTTP 结果，响应体只含 reason + 可读说明，
 * 不回显底层加密库异常。
 */
@RestControllerAdvice
public class EnvelopeExceptionHandler {

    @ExceptionHandler(EnvelopeException.class)
    public ResponseEntity<Map<String, String>> handle(EnvelopeException e) {
        HttpStatus status = switch (e.getReason()) {
            case ACCESS_DENIED -> HttpStatus.FORBIDDEN;
            case VERSION_NOT_FOUND, CIPHERTEXT_MALFORMED, AUTH_TAG_MISMATCH,
                 NONCE_REUSE_DETECTED, KEY_DISABLED_FOR_ENCRYPT, INVALID_ARGUMENT,
                 ROTATION_CONFLICT -> HttpStatus.UNPROCESSABLE_ENTITY;
            case NONCE_GENERATION_FAILED, INTERNAL_CRYPTO_ERROR ->
                    HttpStatus.INTERNAL_SERVER_ERROR;
        };
        return ResponseEntity.status(status).body(Map.of(
                "reason", e.getReason().name(),
                "message", safeMessage(e.getReason())));
    }

    /** 请求体无法读取（坏 JSON / 非法 Base64 / 非法枚举值）统一为 422 INVALID_ARGUMENT。 */
    @ExceptionHandler({HttpMessageNotReadableException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, String>> handleBadRequest(Exception e) {
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(Map.of(
                "reason", RejectReason.INVALID_ARGUMENT.name(),
                "message", safeMessage(RejectReason.INVALID_ARGUMENT)));
    }

    private String safeMessage(RejectReason reason) {
        return switch (reason) {
            case VERSION_NOT_FOUND -> "ciphertext references a key version that does not exist";
            case CIPHERTEXT_MALFORMED -> "ciphertext format cannot be parsed";
            case AUTH_TAG_MISMATCH -> "authentication failed: wrong key or tampered ciphertext";
            case NONCE_REUSE_DETECTED -> "encryption nonce reuse detected; operation rejected";
            case KEY_DISABLED_FOR_ENCRYPT -> "disabled key versions can only decrypt";
            case ACCESS_DENIED -> "caller lacks the required role";
            case ROTATION_CONFLICT -> "rotation could not complete consistently";
            case INVALID_ARGUMENT -> "request argument is invalid";
            case NONCE_GENERATION_FAILED -> "local nonce generation failed";
            case INTERNAL_CRYPTO_ERROR -> "local crypto configuration error";
        };
    }
}
