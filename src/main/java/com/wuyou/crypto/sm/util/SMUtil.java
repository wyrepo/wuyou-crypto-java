package com.wuyou.crypto.sm.util;

import com.wuyou.crypto.sm.consts.Const;
import com.wuyou.crypto.sm.sm2.SM2Helper;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

public class SMUtil {

    /**
     * Read SM2 private key from string (pem format)
     */
    public static PrivateKey readPrivateKeyFromPem(String skPem, String pwd) {
        return SM2Helper.readPrivateKeyFromPem(skPem, pwd);
    }

    /**
     * Read SM2 private key from file (pem format)
     */
    public static PrivateKey readPrivateKeyFromPemFile(String filePath, String pwd) {
        return SM2Helper.readPrivateKeyFromPemFile(filePath, pwd);
    }

    /**
     * Write SM2 private key to string (pem format)
     */
    public static String writePrivateKeyToPem(PrivateKey sk, String pwd) {
        return SM2Helper.writePrivateKeyToPem(sk, pwd);
    }

    /**
     * Write SM2 private key to file (pem format)
     */
    public static boolean writePrivateKeyToPemFile(String filePath, PrivateKey sk, String pwd) {
        return SM2Helper.writePrivateKeyToPemFile(filePath, sk, pwd);
    }

    /**
     * Read SM2 public key from string (pem format)
     */
    public static PublicKey readPublicKeyFromPem(String pkPem) {
        return SM2Helper.readPublicKeyFromPem(pkPem);
    }

    /**
     * Read SM2 public key from file (pem format)
     */
    public static PublicKey readPublicKeyFromPemFile(String filePath) {
        return SM2Helper.readPublicKeyFromPemFile(filePath);
    }

    /**
     * Write SM2 public key to string (pem format)
     */
    public static String writePublicKeyToPem(PublicKey pk) {
        return SM2Helper.writePublicKeyToPem(pk);
    }

    /**
     * Write SM2 public key to file (pem format)
     */
    public static boolean writePublicKeyToPemFile(String filePath, PublicKey pk) {
        return SM2Helper.writePublicKeyToPemFile(filePath, pk);
    }

    /**
     * Read SM2 private key from string (hex format)
     */
    public static PrivateKey readPrivateKeyFromHex(String dHex) {
        byte[] dBytes = Hex.decode(dHex);
        BigInteger d = new BigInteger(1, dBytes);
        try {
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, Const.SPEC);
            return SM2Helper.keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Write SM2 private key to string (hex format)
     */
    public static String writePrivateKeyToHex(PrivateKey key) {
        BCECPrivateKey sk = (BCECPrivateKey) key;
        return Hex.toHexString(sk.getD().toByteArray());
    }

    /**
     * Read SM2 public key from string (hex format)
     */
    public static PublicKey readPublicKeyFromHex(String pkHex) {
        byte[] c = Hex.decode(pkHex);
        ECPoint point = Const.X9EC.getCurve().decodePoint(c);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(EC5Util.convertPoint(point), Const.SPEC);
        try {
            return SM2Helper.keyFactory.generatePublic(pubKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Write SM2 public key to string (hex format)
     */
    public static String writePublicKeyToHex(PublicKey key) {
        BCECPublicKey pk = (BCECPublicKey) key;
        byte[] c = pk.getQ().getEncoded(true);
        return Hex.toHexString(c);
    }

}
