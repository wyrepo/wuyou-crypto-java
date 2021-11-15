package com.wuyou.crypto.paillier.util;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PrivateKeyInfo;
import com.wuyou.crypto.paillier.key.PublicKey;
import com.wuyou.crypto.paillier.key.PublicKeyInfo;
import com.wuyou.crypto.paillier.num.Cipher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;

public class PaillierUtil {

    // Paillier.Cipher to Hex String
    public static String cipherToHexStr(Cipher value) {
        if (value == null) {
            return null;
        }
        BigInteger cipher = value.getCipher();
        if (cipher == null) {
            return null;
        }
        byte[] bytes = cipher.toByteArray();
        return Hex.toHexString(bytes);
    }

    // Hex String to Paillier.Cipher
    public static Cipher hexStrToCipher(PublicKey pk, String s) {
        if (pk == null) {
            return null;
        }
        if (s == null || s.isEmpty()) {
            return null;
        }
        byte[] bytes = Hex.decode(s);
        BigInteger c = new BigInteger(bytes);
        return new Cipher(pk, c);
    }

    public static String writePublicKeyToPem(PublicKey pk) {
        try (StringWriter strWriter = new StringWriter();
             PemWriter pemWriter = new PemWriter(strWriter)) {
            byte[] bytes = serializePublicKey(pk);
            PemObject pemObject = new PemObject("PUBLIC KEY", bytes);
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            return strWriter.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String writePrivateKeyToPem(PrivateKey sk) {
        try (StringWriter strWriter = new StringWriter();
             PemWriter pemWriter = new PemWriter(strWriter)) {
            byte[] bytes = serializePrivateKey(sk);
            PemObject pemObject = new PemObject("PRIVATE KEY", bytes);
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            return strWriter.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PublicKey readPublicKeyFromPem(String pkPem) {
        if (pkPem == null || pkPem.isEmpty()) {
            return null;
        }
        try (StringReader strReader = new StringReader(pkPem);
             PemReader pemReader = new PemReader(strReader)) {
            byte[] bytes = pemReader.readPemObject().getContent();
            if (bytes == null || bytes.length <= 0) {
                return null;
            }
            return deserializePublicKey(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey readPrivateKeyFromPem(String skPem) {
        if (skPem == null || skPem.isEmpty()) {
            return null;
        }
        try (StringReader strReader = new StringReader(skPem);
             PemReader pemReader = new PemReader(strReader)) {
            byte[] bytes = pemReader.readPemObject().getContent();
            if (bytes == null || bytes.length <= 0) {
                return null;
            }
            return deserializePrivateKey(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String serializePublicKeyHex(PublicKey pk) {
        // serialize public key to string (hex format)
        byte[] bytes = serializePublicKey(pk);
        if (bytes == null || bytes.length <= 0) {
            return null;
        }
        return Hex.toHexString(bytes);
    }

    public static byte[] serializePublicKey(PublicKey pk) {
        // serialize public key to bytes
        PublicKeyInfo info = new PublicKeyInfo(pk.getLen(), pk.getN());
        try {
            return info.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] serializePrivateKey(PrivateKey sk) {
        // serialize private key to bytes
        PrivateKeyInfo info = new PrivateKeyInfo(sk.getLen(), sk.getL(), sk.getPublicKey().getN(), sk.getThreshold());
        try {
            return info.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PublicKey deserializePublicKeyHex(String pkHex) {
        // deserialize public key from string (hex format)
        byte[] bytes = Hex.decode(pkHex);
        if (bytes == null || bytes.length <= 0) {
            return null;
        }
        return deserializePublicKey(bytes);
    }

    public static PublicKey deserializePublicKey(byte[] pkBytes) {
        // deserialize public key from bytes
        try (ByteArrayInputStream bos = new ByteArrayInputStream(pkBytes);
             ASN1InputStream in = new ASN1InputStream(bos)) {
            ASN1Primitive primitive = in.readObject();
            if (!(primitive instanceof ASN1Sequence)) {
                return null;
            }
            ASN1Sequence seq = (ASN1Sequence) primitive;
            ASN1SequenceParser parser = seq.parser();
            ASN1Encodable asn1Len = parser.readObject();
            int len = Integer.parseInt(asn1Len.toASN1Primitive().toString());
            if (len <= 0) {
                return null;
            }
            ASN1Encodable asn1N = parser.readObject();
            BigInteger n = new BigInteger(asn1N.toASN1Primitive().toString());
            if (n.signum() <= 0) {
                return null;
            }
            return new PublicKey(len, n);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey deserializePrivateKey(byte[] skBytes) {
        // deserialize private key from bytes
        try (ByteArrayInputStream bos = new ByteArrayInputStream(skBytes);
             ASN1InputStream in = new ASN1InputStream(bos)) {
            ASN1Primitive primitive = in.readObject();
            if (!(primitive instanceof ASN1Sequence)) {
                return null;
            }
            ASN1Sequence seq = (ASN1Sequence) primitive;
            ASN1SequenceParser parser = seq.parser();
            ASN1Encodable asn1Len = parser.readObject();
            int len = Integer.parseInt(asn1Len.toASN1Primitive().toString());
            if (len <= 0) {
                return null;
            }
            ASN1Encodable asn1L = parser.readObject();
            BigInteger l = new BigInteger(asn1L.toASN1Primitive().toString());
            ASN1Encodable asn1N = parser.readObject();
            BigInteger n = new BigInteger(asn1N.toASN1Primitive().toString());
            if (l.signum() <= 0 || n.signum() <= 0) {
                return null;
            }
            ASN1Encodable asn1Threshold = parser.readObject();
            long threshold = Long.parseLong(asn1Threshold.toASN1Primitive().toString());
            return new PrivateKey(len, l, n, threshold);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
