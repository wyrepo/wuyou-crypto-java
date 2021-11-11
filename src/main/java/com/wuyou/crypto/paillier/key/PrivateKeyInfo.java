package com.wuyou.crypto.paillier.key;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;

public class PrivateKeyInfo extends ASN1Object {

    private int len;//bit length
    private BigInteger l;//L
    private BigInteger n;//N
    private long threshold;

    public PrivateKeyInfo(int len, BigInteger l, BigInteger n, long threshold) {
        this.len = len;
        this.l = l;
        this.n = n;
        this.threshold = threshold;
    }

    public int getLen() {
        return len;
    }

    public BigInteger getL() {
        return l;
    }

    public BigInteger getN() {
        return n;
    }

    public long getThreshold() {
        return threshold;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(len));
        vector.add(new ASN1Integer(l));
        vector.add(new ASN1Integer(n));
        vector.add(new ASN1Integer(threshold));
        return new DERSequence(vector);
    }
}
