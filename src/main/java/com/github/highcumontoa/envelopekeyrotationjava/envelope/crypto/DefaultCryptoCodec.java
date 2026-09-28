package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * 基于 JCE AES/GCM/NoPadding 的原语封装。
 *
 * 关键约定：
 * 1) 输入密文约定为 “ciphertext || tag”，tag 固定 128 bit；
 * 2) 解密时认证标签不通过（密文/nonce/key 被篡改或对不上）一律归类为
 *    {@link RejectReason#AUTH_TAG_MISMATCH}，不透出 AEADBadTagException；
 * 3) 密钥长度、算法不可用等本地配置问题归类为 INTERNAL_CRYPTO_ERROR；
 * 4) 密文结构过短等输入问题归类为 CIPHERTEXT_MALFORMED。
 */
public class DefaultCryptoCodec implements CryptoCodec {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / 8;

    @Override
    public byte[] seal(byte[] key, byte[] nonce, byte[] plaintext) {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new EnvelopeException(RejectReason.INTERNAL_CRYPTO_ERROR,
                    "encryption key length is invalid for AES");
        }
        if (nonce == null) {
            throw new EnvelopeException(RejectReason.INTERNAL_CRYPTO_ERROR, "nonce is null");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
        } catch (GeneralSecurityException e) {
            // 本地算法/密钥配置问题，不把 JCE 原始消息透出
            throw new EnvelopeException(RejectReason.INTERNAL_CRYPTO_ERROR,
                    "AES-GCM seal failed due to local crypto configuration", e);
        }
    }

    @Override
    public byte[] open(byte[] key, byte[] nonce, byte[] ciphertextWithTag) {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new EnvelopeException(RejectReason.INTERNAL_CRYPTO_ERROR,
                    "decryption key length is invalid for AES");
        }
        if (nonce == null || ciphertextWithTag == null
                || ciphertextWithTag.length < TAG_BYTES) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "ciphertext or nonce missing, or shorter than GCM tag");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(ciphertextWithTag);
        } catch (AEADBadTagException e) {
            // 密文被篡改 / nonce 被改 / 密钥对不上：认证失败的统一可解释原因
            throw new EnvelopeException(RejectReason.AUTH_TAG_MISMATCH,
                    "GCM authentication failed: key mismatch or ciphertext tampered", e);
        } catch (GeneralSecurityException e) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "AES-GCM open rejected the supplied ciphertext parameters", e);
        }
    }
}
