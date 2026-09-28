package com.github.highcumontoa.envelopekeyrotationjava.envelope.web;

/** 加密/解密响应。只含版本元数据与 Base64 载荷，不含任何密钥材料。 */
public record CiphertextResponse(Integer keyVersion, String base64, String note) {
}
