package com.wuyou.crypto.paillier.num;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PublicKey;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Cipher implements Serializable {

    private Random rng;
    private PublicKey publicKey;
    private BigInteger cipher;

    public Cipher(BigInteger plaintext, PublicKey publicKey) {
        this.rng = new SecureRandom();
        this.publicKey = publicKey;
        this.cipher = encrypt(plaintext);
    }

    public Cipher(PublicKey publicKey, BigInteger cipher) {
        this.rng = new SecureRandom();
        this.publicKey = publicKey;
        this.cipher = cipher;
    }

    private BigInteger encrypt(BigInteger plaintext) {
        BigInteger r;
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSq();
        do {
            r = new BigInteger(publicKey.getLen(), rng);
        } while (r.compareTo(n) >= 0);

        BigInteger g = publicKey.getG();
        // g^m * r^n mod n^2
        return g.modPow(plaintext, nSquared).multiply(r.modPow(n, nSquared)).mod(nSquared);
    }

    public BigInteger decrypt(PrivateKey privateKey) {
        // ((cipher^privateKey.L mod n^2) / n) * u mod n
        BigInteger inputOfLFunction = cipher.modPow(privateKey.getL(), publicKey.getNSq());
        BigInteger outputOfLFunction = inputOfLFunction.subtract(BigInteger.ONE).divide(publicKey.getN());
        BigInteger x = outputOfLFunction.multiply(privateKey.getU()).mod(publicKey.getN());

        // check if m is negative
        if (x.compareTo(BigInteger.valueOf(privateKey.getThreshold())) > 0) {
            // m = m - n
            return x.subtract(publicKey.getN());
        }
        return x;
    }

    public Cipher addCipherText(Cipher other) throws Exception {
        if (!publicKey.equals(other.getPublicKey())) {
            throw new Exception("Cannot perform addCipherText operation with different public keys");
        }
        // x * y mod n^2
        BigInteger resultCipher = cipher.multiply(other.getCipher()).mod(publicKey.getNSq());
        return new Cipher(publicKey, resultCipher);
    }

    public Cipher addPlainText(BigInteger plaintext) {
        // x * g^y mod n^2
        BigInteger g = publicKey.getG();
        BigInteger resultCipher = cipher.multiply(g.modPow(plaintext, publicKey.getNSq())).mod(publicKey.getNSq());
        return new Cipher(publicKey, resultCipher);
    }

    public Cipher subCipherText(Cipher other) throws Exception {
        if (!publicKey.equals(other.getPublicKey())) {
            throw new Exception("Cannot perform addCipherText operation with different public keys");
        }
        // x * -y mod n^2
        BigInteger negOne = BigInteger.ONE.negate();
        BigInteger resultCipher = cipher.multiply(other.mulPlainText(negOne).getCipher()).mod(publicKey.getNSq());
        return new Cipher(publicKey, resultCipher);
    }

    public Cipher mulPlainText(BigInteger plaintext) {
        // x^y mod n^2
        BigInteger resultCipher = cipher.modPow(plaintext, publicKey.getNSq());
        return new Cipher(publicKey, resultCipher);
    }

    public Cipher divPlainText(BigInteger plaintext) throws Exception {
        if (plaintext.intValue() == 0) {
            throw new Exception("Cannot div by 0");
        }
        // x^(y^-1 mod n) mod n^2
        BigInteger operand = plaintext.modInverse(publicKey.getN());
        BigInteger resultCipher = cipher.modPow(operand, publicKey.getNSq());
        return new Cipher(publicKey, resultCipher);
    }

    public void randomize() {
        BigInteger r;
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSq();
        do {
            r = new BigInteger(publicKey.getLen(), rng);
        } while (r.compareTo(n) >= 0);

        BigInteger randomZeroCipher = r.modPow(n, nSquared);
        cipher = cipher.multiply(randomZeroCipher).mod(publicKey.getNSq());
    }

    public static Cipher encryptWithR(BigInteger plaintext, PublicKey publicKey, BigInteger r) {
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSq();
        BigInteger g = publicKey.getG();
        BigInteger cipher = g.modPow(plaintext, nSquared).multiply(r.modPow(n, nSquared)).mod(nSquared);
        return new Cipher(publicKey, cipher);
    }

    public BigInteger getTrapdoorR(PrivateKey privateKey) {
        BigInteger m = decrypt(privateKey);
        BigInteger intermediateC = cipher.modPow(BigInteger.ONE, publicKey.getN()).multiply(publicKey.getG()
                .modPow(m.negate(), publicKey.getN())).mod(publicKey.getN());
        return intermediateC.modPow(publicKey.getN().modPow(BigInteger.ONE.negate(), privateKey.getL()), publicKey.getN());
    }

    public BigInteger getCipher() {
        return cipher;
    }

    public byte[] getCipherBytes() {
        return cipher.toByteArray();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}
