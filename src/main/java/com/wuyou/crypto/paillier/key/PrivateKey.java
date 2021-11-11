package com.wuyou.crypto.paillier.key;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class PrivateKey implements Serializable {

    private PublicKey publicKey;
    private int len;//bit length
    private BigInteger l;//L
    private BigInteger u;//U
    private long threshold;

    public PrivateKey(int len, long threshold) {
        Random rng = new SecureRandom();
        BigInteger p = new BigInteger(len, 20, rng);
        BigInteger q = new BigInteger(len, 20, rng);

        BigInteger n = p.multiply(q);
        this.publicKey = new PublicKey(len, n);
        this.len = len;

        p = p.subtract(BigInteger.ONE);
        q = q.subtract(BigInteger.ONE);
        this.l = p.multiply(q);
        this.u = this.l.modInverse(this.publicKey.getN());
        this.threshold = threshold;
    }

    public PrivateKey(int len, BigInteger l, BigInteger n, long threshold) {
        this.publicKey = new PublicKey(len, n);
        this.len = len;
        this.l = l;
        this.u = this.l.modInverse(n);
        this.threshold = threshold;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public int getLen() {
        return len;
    }

    public BigInteger getL() {
        return l;
    }

    public BigInteger getU() {
        return u;
    }

    public long getThreshold() {
        return threshold;
    }
}
