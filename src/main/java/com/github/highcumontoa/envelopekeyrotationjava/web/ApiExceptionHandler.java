package com.github.highcumontoa.envelopekeyrotationjava.web;

import com.github.highcumontoa.envelopekeyrotationjava.crypto.CiphertextTamperedException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.CryptoOperationException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyRetiredException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.NonceReuseException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.UnknownKeyVersionException;
import com.github.highcumontoa.envelopekeyrotationjava.security.AccessDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 把领域异常映射为确定、可解释的 HTTP 响应。
 * 不泄漏底层加密库信息与任何密钥材料。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleDenied(AccessDeniedException ex) {
        return build(HttpStatus.FORBIDDEN, "ACCESS_DENIED", ex.getMessage(),
                "requiredRole=" + ex.requiredRole());
    }

    @ExceptionHandler(UnknownKeyVersionException.class)
    public ResponseEntity<Map<String, Object>> handleUnknownVersion(
            UnknownKeyVersionException ex) {
        return build(HttpStatus.UNPROCESSABLE_ENTITY, "UNKNOWN_KEY_VERSION", ex.getMessage(),
                "requestedVersion=" + ex.requestedVersion());
    }

    @ExceptionHandler(KeyRetiredException.class)
    public ResponseEntity<Map<String, Object>> handleRetired(KeyRetiredException ex) {
        return build(HttpStatus.CONFLICT, "KEY_RETIRED", ex.getMessage(),
                "version=" + ex.version());
    }

    @ExceptionHandler(NonceReuseException.class)
    public ResponseEntity<Map<String, Object>> handleNonceReuse(NonceReuseException ex) {
        return build(HttpStatus.CONFLICT, "NONCE_REUSE_DETECTED", ex.getMessage(),
                "version=" + ex.version());
    }

    @ExceptionHandler(CiphertextTamperedException.class)
    public ResponseEntity<Map<String, Object>> handleTampered(CiphertextTamperedException ex) {
        return build(HttpStatus.BAD_REQUEST, "CIPHERTEXT_REJECTED", ex.getMessage(), null);
    }

    @ExceptionHandler(CryptoOperationException.class)
    public ResponseEntity<Map<String, Object>> handleCrypto(CryptoOperationException ex) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "CRYPTO_OPERATION_FAILED",
                ex.getMessage(), null);
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, String code,
                                                      String message, String detail) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("time", Instant.now().toString());
        body.put("status", status.value());
        body.put("errorCode", code);
        body.put("message", message);
        if (detail != null) {
            body.put("detail", detail);
        }
        return ResponseEntity.status(status).body(body);
    }
}
