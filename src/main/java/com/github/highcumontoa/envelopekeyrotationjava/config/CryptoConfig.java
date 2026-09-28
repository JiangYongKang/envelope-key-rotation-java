package com.github.highcumontoa.envelopekeyrotationjava.config;

import com.github.highcumontoa.envelopekeyrotationjava.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.EnvelopeCipherService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.InMemoryKeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyRotationService;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.NonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.SecureRandomNonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.security.CallerResolver;
import com.github.highcumontoa.envelopekeyrotationjava.security.PermissionChecker;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 本地信封加密能力的装配。
 * 密钥材料全部来自进程内 SecureRandom，不引入任何外部 KMS；
 * 进程重启后会生成新的初始密钥（本地演示语义）。
 */
@Configuration
public class CryptoConfig {

    private static final int INITIAL_VERSION = 1;

    @Bean
    public AuditLog auditLog() {
        return new InMemoryAuditLog();
    }

    @Bean
    public KeyStore keyStore() {
        byte[] initialKey = new byte[KeyRotationService.KEY_LENGTH_BYTES];
        try {
            new SecureRandom().nextBytes(initialKey);
            return new InMemoryKeyStore(initialKey, INITIAL_VERSION);
        } finally {
            Arrays.fill(initialKey, (byte) 0);
        }
    }

    @Bean
    public NonceGenerator nonceGenerator() {
        return new SecureRandomNonceGenerator();
    }

    @Bean
    public PermissionChecker permissionChecker() {
        return new PermissionChecker();
    }

    @Bean
    public CallerResolver callerResolver() {
        return new CallerResolver();
    }

    @Bean
    public EnvelopeCipherService envelopeCipherService(KeyStore keyStore,
                                                       NonceGenerator nonceGenerator,
                                                       AuditLog auditLog,
                                                       PermissionChecker permissionChecker) {
        return new EnvelopeCipherService(keyStore, nonceGenerator, auditLog, permissionChecker);
    }

    @Bean
    public KeyRotationService keyRotationService(KeyStore keyStore, AuditLog auditLog,
                                                 PermissionChecker permissionChecker) {
        return new KeyRotationService(keyStore, auditLog, permissionChecker);
    }
}
