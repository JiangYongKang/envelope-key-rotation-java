package com.github.highcumontoa.envelopekeyrotationjava.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 信封密文的内存表示与自描述序列化。
 * 二进制布局（小端序）：
 * magic(4)='E','N','V','1' | keyVersion(int32) |
 * wrappedDekLen(int32) | wrappedDek |
 * nonceLen(int32) | nonce |
 * ciphertextLen(int32) | ciphertext(含 GCM 认证标签)
 */
public record EnvelopeCiphertext(int keyVersion,
                                 byte[] wrappedDek,
                                 byte[] nonce,
                                 byte[] payload) {

    private static final byte[] MAGIC = {'E', 'N', 'V', '1'};
    private static final int MAX_FIELD_LENGTH = 1 << 20; // 1 MiB 单字段上限，防御畸形输入

    public byte[] encode() {
        int total = MAGIC.length + 4 + 3 * 4
                + wrappedDek.length + nonce.length + payload.length;
        ByteBuffer buffer = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(MAGIC);
        buffer.putInt(keyVersion);
        putField(buffer, wrappedDek);
        putField(buffer, nonce);
        putField(buffer, payload);
        return buffer.array();
    }

    public static EnvelopeCiphertext decode(byte[] data) {
        if (data == null) {
            throw new CiphertextTamperedException("ciphertext is absent");
        }
        ByteBuffer buffer;
        try {
            buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        } catch (RuntimeException ex) {
            throw new CiphertextTamperedException("unreadable ciphertext bytes");
        }
        if (buffer.remaining() < MAGIC.length + 4) {
            throw new CiphertextTamperedException("ciphertext header truncated");
        }
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        for (int i = 0; i < MAGIC.length; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new CiphertextTamperedException("bad magic, not an envelope ciphertext");
            }
        }
        int version = buffer.getInt();
        if (version <= 0) {
            throw new CiphertextTamperedException("invalid key version in header: " + version);
        }
        byte[] wrappedDek = readField(buffer, "wrappedDek");
        byte[] nonce = readField(buffer, "nonce");
        byte[] payload = readField(buffer, "payload");
        if (buffer.hasRemaining()) {
            throw new CiphertextTamperedException("trailing garbage after ciphertext");
        }
        if (nonce.length == 0) {
            throw new CiphertextTamperedException("empty nonce");
        }
        return new EnvelopeCiphertext(version, wrappedDek, nonce, payload);
    }

    private static void putField(ByteBuffer buffer, byte[] field) {
        buffer.putInt(field.length);
        buffer.put(field);
    }

    private static byte[] readField(ByteBuffer buffer, String fieldName) {
        if (buffer.remaining() < 4) {
            throw new CiphertextTamperedException(fieldName + " length truncated");
        }
        int length = buffer.getInt();
        if (length < 0 || length > MAX_FIELD_LENGTH) {
            throw new CiphertextTamperedException(fieldName + " length out of range: " + length);
        }
        if (buffer.remaining() < length) {
            throw new CiphertextTamperedException(fieldName + " body truncated");
        }
        byte[] field = new byte[length];
        buffer.get(field);
        return field;
    }
}
