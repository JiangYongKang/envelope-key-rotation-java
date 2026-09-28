package com.github.highcumontoa.envelopekeyrotationjava.envelope.web;

import java.util.List;

/**
 * 加密请求。plaintextBase64 为业务明文的 Base64；
 * roles 为本地演示用的调用方角色声明（生产应替换为真实认证）。
 */
public record EncryptRequest(String caller, List<String> roles, String plaintextBase64) {
}
