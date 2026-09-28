package com.github.highcumontoa.envelopekeyrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 端到端：加密-轮换-解密兼容、越权、篡改
 * 以及审计查询，验证 HTTP 状态码与 errorCode 确定可解释。
 */
@SpringBootTest
@AutoConfigureMockMvc
class CryptoControllerIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(CryptoControllerIntegrationTest.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void encryptRotateDecryptFlowOverHttp() throws Exception {
        String v1Cipher = encrypt("svc", "ENCRYPTOR,DECRYPTOR,KEY_ADMIN", "legacy-payload");
        log.info("[http-flow] v1 ciphertext acquired ({} bytes b64)", v1Cipher.length());

        // 越权轮换：只有 ENCRYPTOR
        String deniedBody = mockMvc.perform(post("/api/rotate")
                        .header("X-Caller-Id", "enc-only")
                        .header("X-Caller-Roles", "ENCRYPTOR"))
                .andExpect(status().isForbidden())
                .andDo(r -> log.info("[http-flow] rotate without admin -> {}",
                        r.getResponse().getStatus()))
                .andReturn().getResponse().getContentAsString();
        assertTrue(deniedBody.contains("ACCESS_DENIED"));

        // 合法轮换
        JsonNode rotateResponse = read(mockMvc.perform(post("/api/rotate")
                        .header("X-Caller-Id", "admin")
                        .header("X-Caller-Roles", "KEY_ADMIN"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        int newVersion = rotateResponse.get("rotatedToVersion").asInt();
        log.info("[http-flow] rotated to version {}", newVersion);

        // 新数据走新版本
        JsonNode newEncryption = read(cipherResponseJson(
                "svc", "ENCRYPTOR,DECRYPTOR,KEY_ADMIN", "x"));
        assertEquals(newVersion, newEncryption.get("keyVersion").asInt());
        String v2Cipher = newEncryption.get("ciphertext").asText();

        // 历史密文与新密文都能解
        String legacy = decrypt("svc", "ENCRYPTOR,DECRYPTOR,KEY_ADMIN", v1Cipher);
        String fresh = decrypt("svc", "ENCRYPTOR,DECRYPTOR,KEY_ADMIN", v2Cipher);
        log.info("[http-flow] decision: legacy='{}', fresh='{}'", legacy, fresh);
        assertEquals("legacy-payload", legacy);
        assertEquals("x", fresh);
    }

    @Test
    void tamperedCiphertextReturnsDeterministicError() throws Exception {
        String cipherB64 = encrypt("svc", "ENCRYPTOR,DECRYPTOR", "tamper-me");
        byte[] raw = Base64.getDecoder().decode(cipherB64);
        raw[raw.length - 3] ^= 0x01;
        String tamperedB64 = Base64.getEncoder().encodeToString(raw);

        String body = mockMvc.perform(post("/api/decrypt")
                        .header("X-Caller-Id", "svc")
                        .header("X-Caller-Roles", "DECRYPTOR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + tamperedB64 + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("CIPHERTEXT_REJECTED"))
                .andDo(r -> log.info("[http-tamper] decision body={}",
                        r.getResponse().getContentAsString()))
                .andReturn().getResponse().getContentAsString();
        assertTrue(body.contains("authentication failed"));
    }

    @Test
    void decryptWithoutRoleIsForbiddenAndAudited() throws Exception {
        mockMvc.perform(post("/api/decrypt")
                        .header("X-Caller-Id", "enc-only")
                        .header("X-Caller-Roles", "ENCRYPTOR")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"QUFBQQ\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"));

        JsonNode events = read(mockMvc.perform(get("/api/audit"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        boolean found = false;
        for (JsonNode event : events) {
            if ("DECRYPT_DENIED".equals(event.path("action").asText())
                    && "enc-only".equals(event.path("callerId").asText())) {
                found = true;
                log.info("[http-audit] found denial record: {}", event);
            }
            assertNotNull(event.get("time"));
            assertTrue(!event.toString().contains("keyBytes"));
        }
        assertTrue(found, "expected a DECRYPT_DENIED audit record");
    }

    private String encrypt(String caller, String roles, String plaintext) throws Exception {
        return read(cipherResponseJson(caller, roles, plaintext)).get("ciphertext").asText();
    }

    private String cipherResponseJson(String caller, String roles, String plaintext)
            throws Exception {
        String body = "{\"plaintext\":\""
                + Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8))
                + "\"}";
        return mockMvc.perform(post("/api/encrypt")
                        .header("X-Caller-Id", caller)
                        .header("X-Caller-Roles", roles)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private String decrypt(String caller, String roles, String cipherB64) throws Exception {
        String json = mockMvc.perform(post("/api/decrypt")
                        .header("X-Caller-Id", caller)
                        .header("X-Caller-Roles", roles)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + cipherB64 + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        byte[] plain = Base64.getDecoder().decode(read(json).get("plaintext").asText());
        return new String(plain, StandardCharsets.UTF_8);
    }

    private JsonNode read(String json) throws Exception {
        return mapper.readTree(json);
    }
}
