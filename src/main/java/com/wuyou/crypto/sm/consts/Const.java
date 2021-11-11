package com.wuyou.crypto.sm.consts;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.spec.ECParameterSpec;

public class Const {

    private Const() {
    }

    public static final String EC_NAME = "EC";
    public static final String SM3_WITH_SM2 = "SM3withSM2";
    public static final String CURVE_NAME = "sm2p256v1";
    public static final String SM2 = "sm2";
    public static final String SM3 = "sm3";
    public static final String SM4 = "sm4";

    public static final X9ECParameters X9EC = GMNamedCurves.getByName(Const.CURVE_NAME);
    public static final ECDomainParameters DOMAIN = new ECDomainParameters(X9EC.getCurve(), X9EC.getG(), X9EC.getN());
    public static final ECParameterSpec SPEC = new ECNamedCurveSpec(CURVE_NAME, X9EC.getCurve(), X9EC.getG(), X9EC.getN());
    public static final JcaPEMKeyConverter CONVERTER = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

}