package com.wuyou.crypto.paillier.key;

import java.io.Serializable;
import java.math.BigInteger;

public class PublicKey implements Serializable {

    private int len;//bit length
    private BigInteger n;//N
    private BigInteger nSq;//Nsq n^2
    private BigInteger g;//G

    public PublicKey(int len, BigInteger n) {
        this.len = len;
        this.n = n;
        this.nSq = n.multiply(n);
        this.g = n.add(BigInteger.ONE);
    }

    public int getLen() {
        return len;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getNSq() {
        return nSq;
    }

    public BigInteger getG() {
        return g;
    }

    public boolean equals(PublicKey otherPublicKey) {
        return this.n.equals(otherPublicKey.getN());
    }

}
