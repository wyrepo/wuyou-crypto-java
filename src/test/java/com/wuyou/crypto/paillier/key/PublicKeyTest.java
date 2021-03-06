package com.wuyou.crypto.paillier.key;

import com.wuyou.crypto.paillier.num.Cipher;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class PublicKeyTest {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Random rng;
    private int N_BIT_LENGTH = 1024;
    private int NUMBER_BIT_LENGTH = 63; // must less than 64, Long.MAX_VALUE = 2^63-1

    @Before
    public void setUp() {
        privateKey = new PrivateKey(N_BIT_LENGTH, Long.MAX_VALUE);
        publicKey = privateKey.getPublicKey();
        rng = new SecureRandom();
    }

    @Test
    public void testSerializable() throws IOException, ClassNotFoundException {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        BigInteger expected = cipher.decrypt(privateKey);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(publicKey);

        //load private key from disk or internet
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        PublicKey publicKeyReadFromDiskOrInternet = (PublicKey) ois.readObject();

        Cipher cipher2 = new Cipher(message, publicKeyReadFromDiskOrInternet);
        BigInteger result = cipher2.decrypt(privateKey);

        assertEquals(expected, result);
    }
}