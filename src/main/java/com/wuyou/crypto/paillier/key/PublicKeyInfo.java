package com.wuyou.crypto.paillier.key;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;

public class PublicKeyInfo extends ASN1Object {

    private int len;//bit length
    private BigInteger n;//N

    public PublicKeyInfo(int len, BigInteger n) {
        this.len = len;
        this.n = n;
    }

    public int getLen() {
        return len;
    }

    public BigInteger getN() {
        return n;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(len));
        vector.add(new ASN1Integer(n));
        return new DERSequence(vector);
    }
}
