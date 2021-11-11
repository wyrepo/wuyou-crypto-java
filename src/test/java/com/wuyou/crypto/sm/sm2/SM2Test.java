package com.wuyou.crypto.sm.sm2;

import com.wuyou.crypto.sm.util.SMUtil;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SM2Test {

    private static final byte[] msg = "123456".getBytes(UTF_8);

    @Test
    public void testGenerateKeyPair() {
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String pkHex = SMUtil.writePublicKeyToHex(publicKey);
        String skHex = SMUtil.writePrivateKeyToHex(privateKey);
        System.out.println("publicKey:" + pkHex);
        System.out.println("privateKey:" + skHex);
        PublicKey publicKey2 = SMUtil.readPublicKeyFromHex(pkHex);
        PrivateKey privateKey2 = SMUtil.readPrivateKeyFromHex(skHex);
        Assert.assertEquals(publicKey, publicKey2);
        Assert.assertEquals(privateKey, privateKey2);
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        // generate key pair
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

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
    public void testSignAndVerify() throws Exception {
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

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

}
