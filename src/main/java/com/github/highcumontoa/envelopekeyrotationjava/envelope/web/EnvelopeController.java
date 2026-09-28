package com.github.highcumontoa.envelopekeyrotationjava.envelope.web;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.EnvelopeService;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Caller;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyVersion;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.Role;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * 本地演示门面。调用方与角色直接来自请求体（仅用于本地验证能力，
 * 不是真正的认证；接入生产时应替换为服务端签发的身份凭证）。
 */
@RestController
@RequestMapping("/api/envelope")
public class EnvelopeController {

    private final EnvelopeService service;

    public EnvelopeController(EnvelopeService service) {
        this.service = service;
    }

    @PostMapping("/encrypt")
    public CiphertextResponse encrypt(@RequestBody EncryptRequest request) {
        Caller caller = toCaller(request.caller(), request.roles());
        byte[] plaintext = Base64.getDecoder().decode(request.plaintextBase64());
        byte[] ciphertext = service.encrypt(caller, plaintext);
        int version = service.versions().stream()
                .filter(kv -> kv.getStatus()
                        == com.github.highcumontoa.envelopekeyrotationjava.envelope.model.KeyStatus.ACTIVE)
                .map(KeyVersion::getVersion).max(Integer::compareTo).orElseThrow();
        return new CiphertextResponse(version,
                Base64.getEncoder().encodeToString(ciphertext),
                "encrypted with current ACTIVE key version");
    }

    @PostMapping("/decrypt")
    public CiphertextResponse decrypt(@RequestBody DecryptRequest request) {
        Caller caller = toCaller(request.caller(), request.roles());
        byte[] ciphertext = Base64.getDecoder().decode(request.ciphertextBase64());
        byte[] plaintext = service.decrypt(caller, ciphertext);
        return new CiphertextResponse(null,
                Base64.getEncoder().encodeToString(plaintext),
                "decrypted using the key version embedded in ciphertext");
    }

    @PostMapping("/rotate")
    public RotationResponse rotate(@RequestBody RotateRequest request) {
        Caller caller = toCaller(request.caller(), request.roles());
        int v = service.rotate(caller);
        return new RotationResponse(v, "previous versions retained DISABLED for historical decrypt");
    }

    @GetMapping("/versions")
    public List<KeyVersionView> versions() {
        return service.versions().stream()
                .map(kv -> new KeyVersionView(kv.getVersion(), kv.getStatus().name(),
                        kv.getCreatedAt().toString())).toList();
    }

    private static Caller toCaller(String caller, List<String> roles) {
        Set<Role> parsed = EnumSet.noneOf(Role.class);
        if (roles != null) {
            for (String r : roles) {
                parsed.add(Role.valueOf(Role.class, r.trim().toUpperCase()));
            }
        }
        return new Caller(caller, parsed);
    }

    /** 只暴露版本元数据，绝不包含 KEK 材料。 */
    public record KeyVersionView(int version, String status, String createdAt) {
    }
}
