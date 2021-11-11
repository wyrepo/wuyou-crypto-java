package com.wuyou.crypto.sm.sm4;

import com.wuyou.crypto.sm.consts.Const;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

public class SM4Helper {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static byte[] generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(Const.SM4, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(128, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    public static byte[] encrypt(byte[] input, byte[] key, SM4Mode sm4Mode, byte[] iv) throws Exception {
        return sm4(input, key, sm4Mode, iv, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(byte[] input, byte[] key, SM4Mode sm4Mode, byte[] iv) throws Exception {
        return sm4(input, key, sm4Mode, iv, Cipher.DECRYPT_MODE);
    }

    private static byte[] sm4(byte[] input, byte[] key, SM4Mode sm4Mode, byte[] iv, int mode) throws Exception {
        IvParameterSpec ivParameterSpec = null;
        if (iv != null) {
            ivParameterSpec = new IvParameterSpec(iv);
        }
        SecretKeySpec sm4Key = new SecretKeySpec(key, Const.SM4);
        Cipher cipher = Cipher.getInstance(sm4Mode.getName(), BouncyCastleProvider.PROVIDER_NAME);
        if (ivParameterSpec == null) {
            cipher.init(mode, sm4Key);
        } else {
            cipher.init(mode, sm4Key, ivParameterSpec);
        }
        return cipher.doFinal(input);
    }

}
