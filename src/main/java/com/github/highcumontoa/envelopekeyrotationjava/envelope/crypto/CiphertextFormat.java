package com.github.highcumontoa.envelopekeyrotationjava.envelope.crypto;

import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.EnvelopeException;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.error.RejectReason;
import com.github.highcumontoa.envelopekeyrotationjava.envelope.model.EnvelopeCiphertext;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;

/**
 * 信封密文的本地二进制格式（大端、自描述）：
 * <pre>
 * MAGIC(4)="ENV1" | kekVersion(int) |
 * wrappedDekLen(int) | wrappedDek | dekNonceLen(int) | dekNonce |
 * dataCipherLen(int) | dataCipher | dataNonceLen(int) | dataNonce
 * </pre>
 * 每条密文都自带加密时的 KEK 版本号，轮换后仍可定位历史密钥。
 * 任何解析异常（魔数不符、截断、负长度、声明长度与实际不符）
 * 都归类为 {@link RejectReason#CIPHERTEXT_MALFORMED}，不抛底层 IO 异常。
 */
public final class CiphertextFormat {

    static final byte[] MAGIC = {'E', 'N', 'V', '1'};

    public CiphertextFormat() {
    }

    public byte[] encode(EnvelopeCiphertext ciphertext) {
        if (ciphertext == null) {
            throw new EnvelopeException(RejectReason.INVALID_ARGUMENT, "ciphertext is null");
        }
        validate(ciphertext.wrappedDek(), "wrappedDek");
        validate(ciphertext.dekNonce(), "dekNonce");
        validate(ciphertext.dataCipher(), "dataCipher");
        validate(ciphertext.dataNonce(), "dataNonce");
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(bos)) {
            out.write(MAGIC);
            out.writeInt(ciphertext.kekVersion());
            writeBlob(out, ciphertext.wrappedDek());
            writeBlob(out, ciphertext.dekNonce());
            writeBlob(out, ciphertext.dataCipher());
            writeBlob(out, ciphertext.dataNonce());
            out.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new EnvelopeException(RejectReason.INTERNAL_CRYPTO_ERROR,
                    "failed to encode envelope ciphertext", e);
        }
    }

    public EnvelopeCiphertext decode(byte[] encoded) {
        if (encoded == null || encoded.length < MAGIC.length) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "ciphertext is empty or shorter than magic header");
        }
        byte[] head = Arrays.copyOfRange(encoded, 0, MAGIC.length);
        if (!Arrays.equals(head, MAGIC)) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "ciphertext magic header mismatch");
        }
        try (DataInputStream in =
                     new DataInputStream(new ByteArrayInputStream(encoded))) {
            long skipped = in.skipBytes(MAGIC.length);
            if (skipped != MAGIC.length) {
                throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                        "ciphertext truncated at magic header");
            }
            int kekVersion = in.readInt();
            if (kekVersion < 1) {
                throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                        "ciphertext declares non-positive key version: " + kekVersion);
            }
            byte[] wrappedDek = readBlob(in);
            byte[] dekNonce = readBlob(in);
            byte[] dataCipher = readBlob(in);
            byte[] dataNonce = readBlob(in);
            return new EnvelopeCiphertext(kekVersion, wrappedDek, dekNonce, dataCipher, dataNonce);
        } catch (EOFException e) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "ciphertext truncated: declared length exceeds available bytes", e);
        } catch (IOException e) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "ciphertext is not parseable envelope format", e);
        }
    }

    private static void writeBlob(DataOutputStream out, byte[] blob) throws IOException {
        out.writeInt(blob.length);
        out.write(blob);
    }

    private static byte[] readBlob(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 0) {
            throw new EnvelopeException(RejectReason.CIPHERTEXT_MALFORMED,
                    "ciphertext declares negative segment length: " + len);
        }
        byte[] blob = new byte[len];
        in.readFully(blob); // 字节不足会抛 EOFException
        return blob;
    }

    private static void validate(byte[] blob, String name) {
        if (blob == null || blob.length == 0) {
            throw new EnvelopeException(RejectReason.INVALID_ARGUMENT,
                    name + " must not be empty");
        }
    }
}
