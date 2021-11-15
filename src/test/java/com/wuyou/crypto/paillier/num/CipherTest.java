package com.wuyou.crypto.paillier.num;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PublicKey;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.*;

public class CipherTest {
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
    public void testCreation() {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        assertNotNull(cipher);
    }

    @Test
    public void testEncryption() {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        assertNotEquals(message, cipher.getCipher());
    }

    @Test
    public void testDecryption() {
        BigInteger message = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(message, publicKey);
        BigInteger decrypt = cipher.decrypt(privateKey);
        assertEquals(message, decrypt);
    }

    @Test
    public void testAdditionOfZeroResult() {
        BigInteger a = BigInteger.TEN;
        BigInteger b = BigInteger.TEN.negate();
        BigInteger expected = a.add(b);
        Cipher cipher = new Cipher(a, publicKey);
        cipher = cipher.addPlainText(b);
        assertEquals(expected, cipher.decrypt(privateKey));
    }

    @Test
    public void testBadAdditionOfEncryptedInteger() {
        PrivateKey privateKey2 = new PrivateKey(N_BIT_LENGTH, Long.MAX_VALUE);
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        BigInteger b = new BigInteger(NUMBER_BIT_LENGTH, rng);

        Cipher cipherA = new Cipher(a, publicKey);
        Cipher cipherB = new Cipher(b, privateKey2.getPublicKey());
        try {
            cipherA = cipherA.addCipherText(cipherB);
            fail();
        } catch (Exception e) {
        }
    }

    @Test
    public void testRandomize() {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        a = a.mod(publicKey.getN());
        Cipher cipherA = new Cipher(a, publicKey);
        BigInteger cipherValueA = cipherA.getCipher();
        BigInteger plainValueA = cipherA.decrypt(privateKey);
        cipherA.randomize();
        BigInteger cipherValueA2 = cipherA.getCipher();
        BigInteger plainValueA2 = cipherA.decrypt(privateKey);
        assertNotSame(cipherValueA, cipherValueA2);
        assertEquals(plainValueA, plainValueA2);
    }

    @Test
    public void testSerializableWithCipherValue() {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(a, publicKey);
        BigInteger cipherValue = cipher.getCipher();
        //send cipherValue to receiver
        Cipher cipher2 = new Cipher(publicKey, cipherValue);
        assertEquals(cipher.decrypt(privateKey), cipher2.decrypt(privateKey));
    }

    @Test
    public void testSerializableWithCipherBytes() {
        BigInteger a = new BigInteger(NUMBER_BIT_LENGTH, rng);
        Cipher cipher = new Cipher(a, publicKey);
        byte[] cipherBytes = cipher.getCipherBytes();
        //encode cipherBytes to  base64 or hexadecimal string and send it to receiver or store into disk
        BigInteger cipherValue = new BigInteger(cipherBytes);
        Cipher cipher2 = new Cipher(publicKey, cipherValue);
        assertEquals(cipher.decrypt(privateKey), cipher2.decrypt(privateKey));
    }

    @Test
    public void testCipherEqualsWithTrapdoorRFromPrivateKey() {
        Cipher c1 = new Cipher(new BigInteger("51545454545"), publicKey);
        BigInteger r = c1.getTrapdoorR(privateKey);
        Cipher c2 = Cipher.encryptWithR(new BigInteger("51545454545"), publicKey, r);
        assertEquals(c1.getCipher(), c2.getCipher());
    }

    @Test
    public void testCipherNotEqualsWithTrapdoorRButDifferentPlaintext() {
        Cipher c1 = new Cipher(new BigInteger("51545454545"), publicKey);
        BigInteger r = c1.getTrapdoorR(privateKey);
        Cipher c2 = Cipher.encryptWithR(new BigInteger("1234548787979"), publicKey, r);
        assertNotEquals(c1.getCipher(), c2.getCipher());
    }
}