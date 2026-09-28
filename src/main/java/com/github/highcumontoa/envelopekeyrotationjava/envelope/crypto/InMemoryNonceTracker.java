package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按 KEK 版本记录已使用 nonce 的内存检测器。
 *
 * 并发正确性依赖 {@link Set#add(Object)} 的原子返回值：
 * 同一版本下两个线程即使同时提交相同 nonce，也只有一个 add 返回 true，
 * 另一个必然得到 false，从而上层会拒绝加密而不是照常产出密文。
 *
 * nonce 按 (keyVersion, nonce 内容) 维度登记；GCM 在同一密钥下复用 nonce
 * 是灾难性的（会泄露认证子密钥并允许伪造），因此这里只跟踪
 * “同一 KEK 版本包装 DEK”所用 nonce（该版本的所有加密都共享这把 KEK）。
 */
public class InMemoryNonceTracker implements NonceTracker {

    private final Map<Integer, Set<ByteWrapper>> usedByVersion = new ConcurrentHashMap<>();

    @Override
    public boolean registerIfAbsent(int keyVersion, byte[] nonce) {
        if (nonce == null) {
            return false;
        }
        Set<ByteWrapper> used =
                usedByVersion.computeIfAbsent(keyVersion, k -> ConcurrentHashMap.newKeySet());
        return used.add(new ByteWrapper(nonce.clone()));
    }

    /** byte[] 的值比较包装，不缓存原始引用以防外部数组被事后修改。 */
    private static final class ByteWrapper {
        private final byte[] data;
        private final int hash;

        private ByteWrapper(byte[] data) {
            this.data = data;
            this.hash = Arrays.hashCode(data);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof ByteWrapper other)) {
                return false;
            }
            return Arrays.equals(data, other.data);
        }

        @Override
        public int hashCode() {
            return hash;
        }
    }
}
