package com.github.highcumontoa.envelopekeyrotationjava.envelope.web;

import java.util.List;

/** 解密请求。ciphertextBase64 为 {@code /encrypt} 返回的密文 Base64。 */
public record DecryptRequest(String caller, List<String> roles, String ciphertextBase64) {
}
