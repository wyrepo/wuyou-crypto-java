package com.wuyou.crypto.sm;

import com.wuyou.crypto.sm.sm2.SM2Helper;
import com.wuyou.crypto.sm.sm3.SM3Helper;
import com.wuyou.crypto.sm.sm4.SM4Helper;
import com.wuyou.crypto.sm.sm4.SM4Mode;
import com.wuyou.crypto.sm.util.SMUtil;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SMTest {

    @Test
    public void testSm2KeysOperations() {
        // generate key pair
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String pkHex = SMUtil.writePublicKeyToHex(publicKey);
        String skHex = SMUtil.writePrivateKeyToHex(privateKey);
        System.out.println(pkHex);
        System.out.println(skHex);
        PublicKey publicKey2 = SMUtil.readPublicKeyFromHex(pkHex);
        PrivateKey privateKey2 = SMUtil.readPrivateKeyFromHex(skHex);
        Assert.assertEquals(publicKey, publicKey2);
        Assert.assertEquals(privateKey, privateKey2);

        // write key to pem (pem can be used to serialize)
        String pkPem = SMUtil.writePublicKeyToPem(publicKey);
        String skPem = SMUtil.writePrivateKeyToPem(privateKey, null);
        System.out.println(pkPem);
        System.out.println(skPem);

        String pkPem2 = SMUtil.writePublicKeyToPem(publicKey2);
        String skPem2 = SMUtil.writePrivateKeyToPem(privateKey2, null);
        System.out.println(pkPem2);
        System.out.println(skPem2);// pem is different but it works

        // read key from pem (deserialize from pem)
        PublicKey publicKey3 = SMUtil.readPublicKeyFromPem(pkPem);
        PrivateKey privateKey3 = SMUtil.readPrivateKeyFromPem(skPem, null);
        Assert.assertEquals(publicKey, publicKey3);
        Assert.assertEquals(privateKey, privateKey3);

        // write key to file, read key from file
        boolean w = SMUtil.writePublicKeyToPemFile("pk.pem", publicKey);
        System.out.println("write public key to pem file, result:" + w);
        w = SMUtil.writePrivateKeyToPemFile("sk.pem", privateKey, null);
        System.out.println("write private key to pem file, result:" + w);

        PublicKey publicKey4 = SMUtil.readPublicKeyFromPemFile("pk.pem");
        PrivateKey privateKey4 = SMUtil.readPrivateKeyFromPemFile("sk.pem", null);
        Assert.assertEquals(publicKey, publicKey4);
        Assert.assertEquals(privateKey, privateKey4);
        String pkPem4 = SMUtil.writePublicKeyToPem(publicKey4);
        String skPem4 = SMUtil.writePrivateKeyToPem(privateKey4, null);
        System.out.println(pkPem4);
        System.out.println(skPem4);// pem is different but it works

        byte[] msg = "123456".getBytes(UTF_8);
        System.out.println(new String(msg, UTF_8));
        try {
            // C1C2C3 mode
            byte[] encryptRet123 = SM2Helper.encrypt(publicKey4, msg, SM2Engine.Mode.C1C2C3);
            if (encryptRet123 == null) {
                return;
            }
            System.out.println("SM2 encrypt C1C2C3 mode result:" + Hex.toHexString(encryptRet123));
            byte[] decryptRet123 = SM2Helper.decrypt(privateKey4, encryptRet123, SM2Engine.Mode.C1C2C3);
            if (decryptRet123 == null) {
                return;
            }
            Assert.assertArrayEquals("SM2 encrypt and decrypt C1C2C3 mode failed", msg, decryptRet123);
            System.out.println(new String(decryptRet123, UTF_8));

            // C1C3C2 mode
            byte[] encryptRet132 = SM2Helper.encrypt(publicKey4, msg, SM2Engine.Mode.C1C3C2);
            if (encryptRet132 == null) {
                return;
            }
            System.out.println("SM2 encrypt C1C3C2 mode result:" + Hex.toHexString(encryptRet132));
            byte[] decryptRet132 = SM2Helper.decrypt(privateKey4, encryptRet132, SM2Engine.Mode.C1C3C2);
            if (decryptRet132 == null) {
                return;
            }
            Assert.assertArrayEquals("SM2 encrypt and decrypt C1C3C2 mode failed", msg, decryptRet132);
            System.out.println(new String(decryptRet132, UTF_8));
        } catch (Exception e) {
            System.out.println("SM2 encrypt and decrypt error:" + e.getMessage());
            e.printStackTrace();
        }

    }

    @Test
    public void testSm2EncryptAndDecrypt() {
        // generate key pair
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] msg = "123456".getBytes(UTF_8);
        System.out.println(new String(msg, UTF_8));
        try {
            // C1C2C3 mode
            byte[] encryptRet123 = SM2Helper.encrypt(publicKey, msg, SM2Engine.Mode.C1C2C3);
            if (encryptRet123 == null) {
                return;
            }
            System.out.println("SM2 encrypt C1C2C3 mode result:" + Hex.toHexString(encryptRet123));
            byte[] decryptRet123 = SM2Helper.decrypt(privateKey, encryptRet123, SM2Engine.Mode.C1C2C3);
            if (decryptRet123 == null) {
                return;
            }
            Assert.assertArrayEquals("SM2 encrypt and decrypt C1C2C3 mode failed", msg, decryptRet123);
            System.out.println(new String(decryptRet123, UTF_8));

            // C1C3C2 mode
            byte[] encryptRet132 = SM2Helper.encrypt(publicKey, msg, SM2Engine.Mode.C1C3C2);
            if (encryptRet132 == null) {
                return;
            }
            System.out.println("SM2 encrypt C1C3C2 mode result:" + Hex.toHexString(encryptRet132));
            byte[] decryptRet132 = SM2Helper.decrypt(privateKey, encryptRet132, SM2Engine.Mode.C1C3C2);
            if (decryptRet132 == null) {
                return;
            }
            Assert.assertArrayEquals("SM2 encrypt and decrypt C1C3C2 mode failed", msg, decryptRet132);
            System.out.println(new String(decryptRet132, UTF_8));
        } catch (Exception e) {
            System.out.println("SM2 encrypt and decrypt error:" + e.getMessage());
            e.printStackTrace();
        }
    }

    @Test
    public void testSm2SignAndVerify() {
        // generate key pair
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] msg = "123456".getBytes(UTF_8);
        try {
            // sign and verify
            byte[] sign = SM2Helper.sign(privateKey, msg);
            if (sign == null) {
                return;
            }
            System.out.println("signResult:" + Hex.toHexString(sign));
            boolean ok = SM2Helper.verify(publicKey, msg, sign);
            Assert.assertTrue("sign and verify failed", ok);
        } catch (Exception e) {
            System.out.println("SM2 sign and verify error:" + e.getMessage());
            e.printStackTrace();
        }
    }

    // examples for sm3
    @Test
    public void testSm3Digest() {
        String input = "123456";
        byte[] hash = SM3Helper.digest(input.getBytes(UTF_8));
        Assert.assertNotNull("SM3 test digest failed", hash);
        String hashHex = Hex.toHexString(hash);
        System.out.println("SM3 digest:" + hashHex);
    }

    // examples for sm4
    @Test
    public void testSm4EncryptAndDecrypt() {
        // SM4 key/iv size must be 16 bytes (128 bit)
        byte[] key = "1234567890abcdef".getBytes(UTF_8);
        byte[] iv = "0000000000000000".getBytes(UTF_8);

        byte[] msg = "123456".getBytes(UTF_8);

        // encrypt
        byte[] msgEncrypted = null;
        try {
            msgEncrypted = SM4Helper.encrypt(msg, key, SM4Mode.SM4_CBC_PKCS7Padding, iv);
            System.out.println("msgEncrypted:" + Hex.toHexString(msgEncrypted));
        } catch (Exception e) {
            System.out.println("SM4 encrypt error:" + e.getMessage());
            e.printStackTrace();
        }
        if (msgEncrypted == null || msgEncrypted.length <= 0) {
            return;
        }

        // decrypt
        byte[] msgDecrypted;
        try {
            msgDecrypted = SM4Helper.decrypt(msgEncrypted, key, SM4Mode.SM4_CBC_PKCS7Padding, iv);
            System.out.println("msgDecrypted:" + new String(msgDecrypted, UTF_8));
        } catch (Exception e) {
            System.out.println("SM4 decrypt error:" + e.getMessage());
            e.printStackTrace();
        }
    }

}
