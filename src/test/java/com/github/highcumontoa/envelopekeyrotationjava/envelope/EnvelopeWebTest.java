package com.github.highcumontoa.envelopekeyrotationjava.envelope;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 门面端到端：200/403/422 状态码与 reason 原因码确定可复现。
 */
@SpringBootTest
@AutoConfigureMockMvc
class EnvelopeWebTest {

    private static final Logger log = LoggerFactory.getLogger(EnvelopeWebTest.class);

    @Autowired
    private MockMvc mockMvc;

    private String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void encryptRotateDecryptHistoryOverHttp() throws Exception {
        // 1) v1 加密
        MvcResult enc = mockMvc.perform(post("/api/envelope/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"app1","roles":["ENCRYPTOR"],"plaintextBase64":"%s"}
                                """.formatted(b64("http-e2e"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value(1))
                .andReturn();
        String oldCipher = Json.read(enc.getResponse().getContentAsString(), "base64");
        log.info("[TEST-JUDGE] scenario=http-encrypt ciphertextB64Len={}", oldCipher.length());

        // 2) 轮换（只有 ROTATOR）
        mockMvc.perform(post("/api/envelope/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"ops1","roles":["ROTATOR"]}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeKeyVersion").value(2));

        // 3) 新版本加密
        MvcResult enc2 = mockMvc.perform(post("/api/envelope/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"app1","roles":["ENCRYPTOR"],"plaintextBase64":"%s"}
                                """.formatted(b64("after-rotation"))))
                .andExpect(jsonPath("$.keyVersion").value(2))
                .andReturn();
        String newCipher = Json.read(enc2.getResponse().getContentAsString(), "base64");

        // 4) 历史密文仍可解（DECRYPTOR），新版本密文也可解
        mockMvc.perform(post("/api/envelope/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"ro1","roles":["DECRYPTOR"],"ciphertextBase64":"%s"}
                                """.formatted(oldCipher)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.base64").value(b64("http-e2e")));
        mockMvc.perform(post("/api/envelope/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"ro1","roles":["DECRYPTOR"],"ciphertextBase64":"%s"}
                                """.formatted(newCipher)))
                .andExpect(jsonPath("$.base64").value(b64("after-rotation")));

        mockMvc.perform(get("/api/envelope/versions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].status").value("DISABLED"))
                .andExpect(jsonPath("$[1].status").value("ACTIVE"));
        log.info("[TEST-JUDGE] scenario=http-history-decrypt result=PASS");
    }

    @Test
    void httpOverreachReturnsForbiddenWithReason() throws Exception {
        log.info("[TEST-INPUT] scenario=http-access-denied ENCRYPTOR tries to rotate");
        mockMvc.perform(post("/api/envelope/rotate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"app1","roles":["ENCRYPTOR"]}"""))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("ACCESS_DENIED"));
    }

    @Test
    void httpTamperedCiphertextReturnsUnprocessableWithReason() throws Exception {
        MvcResult enc = mockMvc.perform(post("/api/envelope/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"app1","roles":["ENCRYPTOR"],"plaintextBase64":"%s"}
                                """.formatted(b64("tamper-me"))))
                .andReturn();
        byte[] raw = Base64.getDecoder().decode(Json.read(enc.getResponse().getContentAsString(), "base64"));
        raw[raw.length - 1] ^= 0x01;
        String tamperedB64 = Base64.getEncoder().encodeToString(raw);

        mockMvc.perform(post("/api/envelope/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"ro1","roles":["DECRYPTOR"],"ciphertextBase64":"%s"}
                                """.formatted(tamperedB64)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.reason").value("AUTH_TAG_MISMATCH"));
        log.info("[TEST-JUDGE] scenario=http-tamper mapped=422/AUTH_TAG_MISMATCH");
    }

    @Test
    void httpInvalidBase64ReturnsUnprocessableInvalidArgument() throws Exception {
        log.info("[TEST-INPUT] scenario=http-invalid-base64");
        mockMvc.perform(post("/api/envelope/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"caller":"ro1","roles":["DECRYPTOR"],"ciphertextBase64":"@@@not-base64@@@"}
                                """))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.reason").value("INVALID_ARGUMENT"));
    }

    /** 极简 JSON 字段提取，避免引入额外依赖。 */
    private static final class Json {
        static String read(String body, String field) {
            String key = "\"" + field + "\":\"";
            int start = body.indexOf(key);
            if (start < 0) {
                throw new IllegalStateException("field not found: " + field);
            }
            start += key.length();
            int end = body.indexOf('"', start);
            return body.substring(start, end);
        }
    }
}
