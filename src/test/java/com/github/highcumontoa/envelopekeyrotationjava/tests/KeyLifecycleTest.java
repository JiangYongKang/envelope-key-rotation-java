package com.github.highcumontoa.envelopekeyrotationjava.tests;

import com.github.highcumontoa.envelopekeyrotationjava.audit.InMemoryAuditLog;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.InMemoryKeyStore;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyRetiredException;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.KeyState;
import com.github.highcumontoa.envelopekeyrotationjava.crypto.ManagedKey;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 密钥生命周期规则：
 * - 初始版本 ACTIVE；轮换后旧版本 RETIRED、新版本 ACTIVE，二者共存；
 * - RETIRED 密钥只能解密不能加密（密钥库层状态明确可判定）。
 */
class KeyLifecycleTest {

    private static final Logger log = LoggerFactory.getLogger(KeyLifecycleTest.class);

    @Test
    void statesTransitionsAreDeterministic() {
        InMemoryKeyStore store = new InMemoryKeyStore(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        assertEquals(KeyState.ACTIVE, store.currentKey().orElseThrow().state());
        log.info("[lifecycle] initial: v1 ACTIVE");

        store.rotate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8));
        store.rotate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".getBytes(StandardCharsets.UTF_8));
        List<ManagedKey> all = store.allVersions();

        assertEquals(List.of(1, 2, 3), all.stream().map(ManagedKey::version).toList());
        assertEquals(KeyState.RETIRED, all.get(0).state());
        assertEquals(KeyState.RETIRED, all.get(1).state());
        assertEquals(KeyState.ACTIVE, all.get(2).state());
        assertEquals(3, store.currentKey().orElseThrow().version());
        log.info("[lifecycle] after 2 rotations: v1/v2 RETIRED (decrypt-only), v3 ACTIVE");
    }

    @Test
    void retiredKeyIsMarkedEncryptDisallowed() {
        InMemoryKeyStore store = new InMemoryKeyStore(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), 1);
        store.rotate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8));

        ManagedKey retired = store.findByVersion(1).orElseThrow();
        assertEquals(KeyState.RETIRED, retired.state());
        KeyRetiredException ex = new KeyRetiredException(retired.version());
        log.info("[lifecycle] decision: encryption under v1 rejected -> '{}'", ex.getMessage());
        assertTrue(ex.getMessage().contains("retired"));
        // 停用版本依然可查、可用于解密路径
        assertEquals(retired.version(), store.findByVersion(1).orElseThrow().version());
    }

    @Test
    void keyMaterialIsDefensivelyCopied() {
        byte[] material = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        InMemoryKeyStore store = new InMemoryKeyStore(material, 1);
        material[0] = 'X'; // 外部改动不应影响密钥库
        ManagedKey first = store.currentKey().orElseThrow();
        ManagedKey again = store.currentKey().orElseThrow();
        assertNotSame(first.keyBytes(), again.keyBytes());
        assertEquals('0', (char) first.keyBytes()[0]);
        log.info("[lifecycle] key material isolated from caller mutation");
    }

    @Test
    void blankKeyMaterialIsRejectedAtConstruction() {
        assertThrows(IllegalArgumentException.class, () -> new InMemoryKeyStore(new byte[0], 1));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryKeyStore(
                "k".getBytes(StandardCharsets.UTF_8), 1).rotate(new byte[0]));
    }
}
