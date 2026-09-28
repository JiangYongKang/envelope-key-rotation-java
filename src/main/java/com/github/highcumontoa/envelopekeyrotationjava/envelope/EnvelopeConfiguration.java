package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.AuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.auth.AccessControl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.auth.RoleAccessControl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CiphertextFormat;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.CryptoCodec;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.DefaultCryptoCodec;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.InMemoryNonceTracker;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProvider;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.LocalKeyMaterialProviderImpl;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.NonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.NonceTracker;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto.SecureRandomNonceGenerator;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.InMemoryKeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.store.KeyStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 本地信封加密能力的 Spring 装配（骨架）。 */
@Configuration
public class EnvelopeConfiguration {

    @Bean
    public LocalKeyMaterialProvider localKeyMaterialProvider() {
        return new LocalKeyMaterialProviderImpl();
    }

    @Bean
    public NonceGenerator nonceGenerator() {
        return new SecureRandomNonceGenerator();
    }

    @Bean
    public CryptoCodec cryptoCodec() {
        return new DefaultCryptoCodec();
    }

    @Bean
    public NonceTracker nonceTracker() {
        return new InMemoryNonceTracker();
    }

    @Bean
    public AccessControl accessControl() {
        return new RoleAccessControl();
    }

    @Bean
    public AuditLog auditLog() {
        return new InMemoryAuditLog();
    }

    @Bean
    public KeyStore keyStore(LocalKeyMaterialProvider provider) {
        return new InMemoryKeyStore(provider);
    }

    @Bean
    public CiphertextFormat ciphertextFormat() {
        return new CiphertextFormat();
    }

    @Bean
    public EnvelopeService envelopeService(KeyStore keyStore, CryptoCodec cryptoCodec,
                                           NonceGenerator nonceGenerator, NonceTracker nonceTracker,
                                           LocalKeyMaterialProvider localKeyMaterialProvider,
                                           AccessControl accessControl, AuditLog auditLog,
                                           CiphertextFormat ciphertextFormat) {
        return new DefaultEnvelopeService(keyStore, cryptoCodec, nonceGenerator, nonceTracker,
                localKeyMaterialProvider, accessControl, auditLog, ciphertextFormat);
    }
}
