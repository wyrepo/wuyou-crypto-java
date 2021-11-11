package com.wuyou.crypto.sm.sm2;

import com.wuyou.crypto.sm.consts.Const;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class SM2Helper {

    private static KeyPairGenerator generator;
    private static Signature signature;
    public static KeyFactory keyFactory;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            generator = KeyPairGenerator.getInstance(Const.EC_NAME, BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(new ECGenParameterSpec(Const.CURVE_NAME));
            signature = Signature.getInstance(Const.SM3_WITH_SM2, BouncyCastleProvider.PROVIDER_NAME);
            keyFactory = KeyFactory.getInstance(Const.EC_NAME, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public static KeyPair generateKeyPair() {
        try {
            return generator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encrypt(PublicKey key, byte[] msg, SM2Engine.Mode mode) {
        SM2Engine engine = new SM2Engine(mode);
        BCECPublicKey pk = (BCECPublicKey) key;
        ECPublicKeyParameters pkParams = new ECPublicKeyParameters(pk.getQ(), Const.DOMAIN);
        engine.init(true, new ParametersWithRandom(pkParams, new SecureRandom()));
        try {
            return engine.processBlock(msg, 0, msg.length);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decrypt(PrivateKey key, byte[] msg, SM2Engine.Mode mode) {
        SM2Engine engine = new SM2Engine(mode);
        BCECPrivateKey sk = (BCECPrivateKey) key;
        ECPrivateKeyParameters skParams = new ECPrivateKeyParameters(sk.getD(), Const.DOMAIN);
        engine.init(false, skParams);
        try {
            return engine.processBlock(msg, 0, msg.length);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] sign(PrivateKey key, byte[] msg) {
        try {
            signature.initSign(key, new SecureRandom());
            signature.update(msg);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verify(PublicKey key, byte[] msg, byte[] sign) {
        try {
            signature.initVerify(key);
            signature.update(msg);
            return signature.verify(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String writePrivateKeyToPem(PrivateKey key, String pwd) {
        OutputEncryptor en = null;
        try (StringWriter strWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter)) {
            if (pwd != null && pwd.length() > 0) {
                //FIXME download and install JCE for JDK8 (ref: https://www.cnblogs.com/kancy/p/13276434.html)
                en = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .setRandom(new SecureRandom())
                        .setPasssword(pwd.toCharArray())
                        .build();
            }
            PKCS8Generator generator = new JcaPKCS8Generator(key, en);
            pemWriter.writeObject(generator);
            pemWriter.flush();
            return strWriter.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean writePrivateKeyToPemFile(String filePath, PrivateKey key, String pwd) {
        OutputEncryptor en = null;
        try (FileWriter fileWriter = new FileWriter(filePath);
             JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {
            if (pwd != null && pwd.length() > 0) {
                //FIXME download and install JCE for JDK8 (ref: https://www.cnblogs.com/kancy/p/13276434.html)
                en = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .setRandom(new SecureRandom())
                        .setPasssword(pwd.toCharArray())
                        .build();
            }
            PKCS8Generator generator = new JcaPKCS8Generator(key, en);
            pemWriter.writeObject(generator);
            pemWriter.flush();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String writePublicKeyToPem(PublicKey key) {
        try (StringWriter strWriter = new StringWriter();
             PemWriter pemWriter = new PemWriter(strWriter)) {
            PemObject pem = new PemObject("PUBLIC KEY", key.getEncoded());
            pemWriter.writeObject(pem);
            pemWriter.flush();
            return strWriter.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean writePublicKeyToPemFile(String filePath, PublicKey key) {
        try (FileWriter fileWriter = new FileWriter(filePath);
             PemWriter pemWriter = new PemWriter(fileWriter)) {
            PemObject pem = new PemObject("PUBLIC KEY", key.getEncoded());
            pemWriter.writeObject(pem);
            pemWriter.flush();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static PrivateKey readPrivateKeyFromPemFile(String filePath, String pwd) {
        try (FileReader reader = new FileReader(filePath);
             PEMParser parser = new PEMParser(reader)) {
            Object info = parser.readObject();
            if (pwd != null && pwd.length() > 0) {
                if (info instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo skInfo = (PKCS8EncryptedPrivateKeyInfo) info;
                    InputDecryptorProvider de = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(pwd.toCharArray());
                    PrivateKeyInfo pkInfo = skInfo.decryptPrivateKeyInfo(de);
                    return Const.CONVERTER.getPrivateKey(pkInfo);
                }
            } else {
                return Const.CONVERTER.getPrivateKey((PrivateKeyInfo) info);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey readPrivateKeyFromPem(String pem, String pwd) {
        try (StringReader reader = new StringReader(pem);
             PEMParser parser = new PEMParser(reader)) {
            Object info = parser.readObject();
            if (pwd != null && pwd.length() > 0) {
                if (info instanceof PKCS8EncryptedPrivateKeyInfo) {
                    PKCS8EncryptedPrivateKeyInfo skInfo = (PKCS8EncryptedPrivateKeyInfo) info;
                    InputDecryptorProvider de = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(pwd.toCharArray());
                    PrivateKeyInfo pkInfo = skInfo.decryptPrivateKeyInfo(de);
                    return Const.CONVERTER.getPrivateKey(pkInfo);
                }
            } else {
                return Const.CONVERTER.getPrivateKey((PrivateKeyInfo) info);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PublicKey readPublicKeyFromPemFile(String filePath) {
        try (FileReader fileReader = new FileReader(filePath);
             PemReader pemReader = new PemReader(fileReader)) {
            PemObject info = pemReader.readPemObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(info.getContent());
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PublicKey readPublicKeyFromPem(String pem) {
        try (StringReader strReader = new StringReader(pem);
             PemReader pemReader = new PemReader(strReader)) {
            PemObject info = pemReader.readPemObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(info.getContent());
            return keyFactory.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String writeCertReqToPem(PKCS10CertificationRequest req) {
        try (StringWriter strWriter = new StringWriter();
             PemWriter pemWriter = new PemWriter(strWriter)) {
            PemObject pem = new PemObject("CERTIFICATE REQUEST", req.getEncoded());
            pemWriter.writeObject(pem);
            pemWriter.flush();
            return strWriter.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String writeCertToPem(X509Certificate cert) {
        try (StringWriter strWriter = new StringWriter();
             PemWriter pemWriter = new PemWriter(strWriter)) {
            PemObject pem = new PemObject("CERTIFICATE", cert.getEncoded());
            pemWriter.writeObject(pem);
            pemWriter.flush();
            return strWriter.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X509Certificate readCertFromPemFile(String filePath) {
        try (FileInputStream in = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(in);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PKCS10CertificationRequest generateCSR(KeyPair keyPair, X500Principal p) {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(Const.SM3_WITH_SM2).build(keyPair.getPrivate());
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(p, keyPair.getPublic());
            return builder.build(signer);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}