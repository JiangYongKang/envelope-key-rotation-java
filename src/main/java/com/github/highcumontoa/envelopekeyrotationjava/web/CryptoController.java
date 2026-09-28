package com.github.highcumontoa.envelopekeyrotationjava.web;

import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditEvent;
import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.EnvelopeCipherService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyRotationService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.ManagedKey;
import com.github.highcumontoa.envelopekeyrotationjava.security.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.security.CallerResolver;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 信封加密 / 解密 / 轮换 / 审计查询入口。
 * 明文/密文均以 Base64 文本放在 JSON 字段中传输，不出现密钥材料。
 */
@RestController
@RequestMapping("/api")
public class CryptoController {

    public record CipherRequest(String plaintext, String ciphertext) {
    }

    private final EnvelopeCipherService cipherService;
    private final KeyRotationService rotationService;
    private final KeyStore keyStore;
    private final AuditLog auditLog;
    private final CallerResolver callerResolver;

    public CryptoController(EnvelopeCipherService cipherService,
                            KeyRotationService rotationService,
                            KeyStore keyStore,
                            AuditLog auditLog,
                            CallerResolver callerResolver) {
        this.cipherService = cipherService;
        this.rotationService = rotationService;
        this.keyStore = keyStore;
        this.auditLog = auditLog;
        this.callerResolver = callerResolver;
    }

    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestHeader("X-Caller-Id") String callerId,
                                       @RequestHeader(value = "X-Caller-Roles", required = false)
                                       String roles,
                                       @RequestBody CipherRequest request) {
        Caller caller = callerResolver.resolve(callerId, roles);
        if (request == null || request.plaintext() == null) {
            throw new IllegalArgumentException("field 'plaintext' (base64) is required");
        }
        byte[] plaintext = Base64.getDecoder().decode(request.plaintext());
        byte[] ciphertext = cipherService.encrypt(caller, plaintext);
        int currentVersion = keyStore.currentKey().map(ManagedKey::version).orElse(-1);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("keyVersion", currentVersion);
        response.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        return response;
    }

    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestHeader("X-Caller-Id") String callerId,
                                       @RequestHeader(value = "X-Caller-Roles", required = false)
                                       String roles,
                                       @RequestBody CipherRequest request) {
        Caller caller = callerResolver.resolve(callerId, roles);
        if (request == null || request.ciphertext() == null) {
            throw new IllegalArgumentException("field 'ciphertext' (base64) is required");
        }
        byte[] rawCiphertext;
        try {
            rawCiphertext = Base64.getDecoder().decode(request.ciphertext());
        } catch (IllegalArgumentException badBase64) {
            throw new com.github.highcumontoa.envelopekeyrotationjava.crypto
                    .CiphertextTamperedException("ciphertext is not valid base64");
        }
        byte[] plaintext = cipherService.decrypt(caller, rawCiphertext);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("keyVersion",
                com.github.highcumontoa.envelopekeyrotationjava.crypto
                        .EnvelopeCiphertext.decode(rawCiphertext).keyVersion());
        response.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
        return response;
    }

    @PostMapping("/rotate")
    public Map<String, Object> rotate(@RequestHeader("X-Caller-Id") String callerId,
                                      @RequestHeader(value = "X-Caller-Roles", required = false)
                                      String roles) {
        Caller caller = callerResolver.resolve(callerId, roles);
        int newVersion = rotationService.rotate(caller);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("rotatedToVersion", newVersion);
        response.put("retainedVersions", keyStore.allVersions().size());
        return response;
    }

    @GetMapping("/audit")
    public List<AuditEvent> auditEvents() {
        return auditLog.events();
    }
}
