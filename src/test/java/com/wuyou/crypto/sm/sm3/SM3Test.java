package com.wuyou.crypto.sm.sm3;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SM3Test {

    @Test
    public void testSm3Digest() {
        String input = "123456";
        byte[] ret = SM3Helper.digest(input.getBytes(UTF_8));

        Assert.assertNotNull("SM3 test digest failed!", ret);
        System.out.println("sm3 digest result:" + Hex.toHexString(ret));
    }

}
