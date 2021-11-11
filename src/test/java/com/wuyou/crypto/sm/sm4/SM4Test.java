package com.wuyou.crypto.sm.sm4;

import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;

public class SM4Test {

    @Test
    public void testGenerateKey() throws Exception {
        byte[] key = SM4Helper.generateKey();
        Assert.assertNotNull("test SM4 generate key failed!", key);
        System.out.println(String.format("key:%s", Hex.encodeHexString(key)));
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        String inputHex = "0123456789ABCDEF0123456789ABCDEF";
        String keyHex = "4D744E003D713D054E7E407C350E447E";
        String ivHex = "4F723F7349774F063C0C477A367B3278";

        for (SM4Mode e : SM4Mode.values()) {
            byte[] iv = null;
            if (!e.getName().contains("ECB")) {
                iv = Hex.decodeHex(ivHex.toCharArray());
            }

            byte[] encryptRet = SM4Helper.encrypt(Hex.decodeHex(inputHex.toCharArray()), Hex.decodeHex(keyHex.toCharArray()), e, iv);
            System.out.println(String.format("SM4 mode = %s, encryptRet = %s", e.getName(), Hex.encodeHexString(encryptRet)));
            byte[] decryptRet = SM4Helper.decrypt(encryptRet, Hex.decodeHex(keyHex.toCharArray()), e, iv);
            Assert.assertEquals(String.format("SM4 %s test encrypt and decrypt failed!", e.getName()), inputHex, Hex.encodeHexString(decryptRet).toUpperCase());
        }
    }

}
