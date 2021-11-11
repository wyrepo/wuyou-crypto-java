package com.wuyou.crypto.sm.sm3;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class SM3Helper {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static byte[] digest(byte[] input) {
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(input, 0, input.length);
        byte[] ret = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(ret, 0);
        return ret;
    }

}
