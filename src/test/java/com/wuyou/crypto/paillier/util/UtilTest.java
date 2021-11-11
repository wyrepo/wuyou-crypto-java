package com.wuyou.crypto.paillier.util;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PublicKey;
import com.wuyou.crypto.paillier.num.Cipher;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;

public class UtilTest {

    @Test
    public void testKeyConverting() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();

        // addCipherText using original operands
        BigInteger x = new BigInteger("100000");
        BigInteger y = new BigInteger("20");
        Cipher eX = new Cipher(x, publicKey);
        Cipher eY = new Cipher(y, publicKey);
        BigInteger sum = eX.addCipherText(eY).decrypt(privateKey);

        // Paillier.Cipher to Hex String (serialize)
        String eXStr = Util.cipherToHexStr(eX);
        if (eXStr == null || eXStr.isEmpty()) {
            return;
        }
        System.out.println("eX HexStr:" + eXStr);
        String eYStr = Util.cipherToHexStr(eY);
        if (eYStr == null || eYStr.isEmpty()) {
            return;
        }
        System.out.println("eY HexStr:" + eYStr);

        // Hex string to Paillier.Cipher (deserialize)
        Cipher eXNum = Util.hexStrToCipher(publicKey, eXStr);
        if (eXNum == null) {
            return;
        }
        Cipher eYNum = Util.hexStrToCipher(publicKey, eYStr);
        if (eYNum == null) {
            return;
        }

        // addCipherText using new operands
        BigInteger sum2 = eXNum.addCipherText(eYNum).decrypt(privateKey);
        System.out.println("sum:" + sum.toString());
        System.out.println("sum2:" + sum2.toString());
    }

    @Test
    public void testKeySerializeAndDeserialize() {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();

        System.out.println("pk.len:" + publicKey.getLen());
        System.out.println("pk.N:" + publicKey.getN());
        System.out.println("pk.Nsq:" + publicKey.getNSq());
        System.out.println("pk.G:" + publicKey.getG());
        System.out.println("sk.len:" + privateKey.getLen());
        System.out.println("sk.L:" + privateKey.getL());
        System.out.println("sk.U:" + privateKey.getU());
        System.out.println("sk.Threshold:" + privateKey.getThreshold());

        // serialize public key
        byte[] bytes = Util.serializePublicKey(publicKey);
        if (bytes == null || bytes.length <= 0) {
            return;
        }
        // deserialize public key
        PublicKey pk = Util.deserializePublicKey(bytes);
        if (pk == null) {
            return;
        }
        System.out.println("-pk.len:" + pk.getLen());
        System.out.println("-pk.N:" + pk.getN());
        System.out.println("-pk.Nsq:" + pk.getNSq());
        System.out.println("-pk.G:" + pk.getG());

        // serialize private key
        byte[] bytes2 = Util.serializePrivateKey(privateKey);
        if (bytes2 == null || bytes2.length <= 0) {
            return;
        }
        // deserialize private key
        PrivateKey sk = Util.deserializePrivateKey(bytes2);
        if (sk == null) {
            return;
        }
        System.out.println("--pk.len:" + sk.getPublicKey().getLen());
        System.out.println("--pk.N:" + sk.getPublicKey().getN());
        System.out.println("--pk.Nsq:" + sk.getPublicKey().getNSq());
        System.out.println("--pk.G:" + sk.getPublicKey().getG());
        System.out.println("-sk.len:" + sk.getLen());
        System.out.println("-sk.L:" + sk.getL());
        System.out.println("-sk.U:" + sk.getU());
        System.out.println("-sk.Threshold:" + sk.getThreshold());
    }

    @Test
    public void testKeyWriteAndRead() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();

        System.out.println("pk.len:" + publicKey.getLen());
        System.out.println("pk.N:" + publicKey.getN());
        System.out.println("pk.Nsq:" + publicKey.getNSq());
        System.out.println("pk.G:" + publicKey.getG());
        System.out.println("sk.len:" + privateKey.getLen());
        System.out.println("sk.L:" + privateKey.getL());
        System.out.println("sk.U:" + privateKey.getU());
        System.out.println("sk.Threshold:" + privateKey.getThreshold());

        // write public key to pem file
        String pkPem = Util.writePublicKeyToPem(publicKey);
        if (pkPem == null || pkPem.isEmpty()) {
            return;
        }
        System.out.println(pkPem);
        Files.write(Paths.get("publickey.key"), pkPem.getBytes(UTF_8));

        // read public key from pem file
        pkPem = new String(Files.readAllBytes(Paths.get("publickey.key")), UTF_8);
        PublicKey pk = Util.readPublicKeyFromPem(pkPem);
        if (pk == null) {
            return;
        }
        System.out.println("-pk.len:" + pk.getLen());
        System.out.println("-pk.N:" + pk.getN());
        System.out.println("-pk.Nsq:" + pk.getNSq());
        System.out.println("-pk.G:" + pk.getG());

        // write private key to pem file
        String skPem = Util.writePrivateKeyToPem(privateKey);
        if (skPem == null || skPem.isEmpty()) {
            return;
        }
        System.out.println(skPem);
        Files.write(Paths.get("privatekey.key"), skPem.getBytes(UTF_8));

        // read private key from pem file
        skPem = new String(Files.readAllBytes(Paths.get("privatekey.key")), UTF_8);
        PrivateKey sk = Util.readPrivateKeyFromPem(skPem);
        if (sk == null) {
            return;
        }
        System.out.println("--pk.len:" + sk.getPublicKey().getLen());
        System.out.println("--pk.N:" + sk.getPublicKey().getN());
        System.out.println("--pk.Nsq:" + sk.getPublicKey().getNSq());
        System.out.println("--pk.G:" + sk.getPublicKey().getG());
        System.out.println("-sk.len:" + sk.getLen());
        System.out.println("-sk.L:" + sk.getL());
        System.out.println("-sk.U:" + sk.getU());
        System.out.println("-sk.Threshold:" + sk.getThreshold());
    }

    @Test
    public void testCross() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println("pk.len:" + publicKey.getLen());
        System.out.println("pk.N:" + publicKey.getN());
        System.out.println("pk.Nsq:" + publicKey.getNSq());
        System.out.println("pk.G:" + publicKey.getG());
        System.out.println("sk.len:" + privateKey.getLen());
        System.out.println("sk.L:" + privateKey.getL());
        System.out.println("sk.U:" + privateKey.getU());
        System.out.println("sk.Threshold:" + privateKey.getThreshold());

        // STEP1: write public/private key to pem file
        String pkPem = Util.writePublicKeyToPem(publicKey);
        if (pkPem == null || pkPem.isEmpty()) {
            return;
        }
        System.out.println(pkPem);
        Files.write(Paths.get("publickey.key"), pkPem.getBytes(UTF_8));
        String skPem = Util.writePrivateKeyToPem(privateKey);
        if (skPem == null || skPem.isEmpty()) {
            return;
        }
        System.out.println(skPem);
        Files.write(Paths.get("privatekey.key"), skPem.getBytes(UTF_8));

        // STEP2: serialize public/private key
        byte[] bytes = Util.serializePublicKey(publicKey);
        if (bytes == null || bytes.length <= 0) {
            return;
        }
        String pkHex = Hex.toHexString(bytes);
        System.out.println("pkHex:" + pkHex);
        byte[] bytes2 = Util.serializePrivateKey(privateKey);
        if (bytes2 == null || bytes2.length <= 0) {
            return;
        }
        String skHex = Hex.toHexString(bytes2);
        System.out.println("skHex:" + skHex);

        // STEP3: operate with public/private key
        BigInteger x = new BigInteger("100000");
        BigInteger y = new BigInteger("20");
        Cipher eX = new Cipher(x, publicKey);
        Cipher eY = new Cipher(y, publicKey);
        BigInteger sum = eX.addCipherText(eY).decrypt(privateKey);
        System.out.println("sum:" + sum.toString());
        String eXStr = Util.cipherToHexStr(eX);
        if (eXStr == null || eXStr.isEmpty()) {
            return;
        }
        System.out.println("eX HexStr:" + eXStr);
        String eYStr = Util.cipherToHexStr(eY);
        if (eYStr == null || eYStr.isEmpty()) {
            return;
        }
        System.out.println("eY HexStr:" + eYStr);
    }

    @Test
    public void testCross2() throws Exception {
        // STEP1: read public/private key from pem file
        String pkPem = new String(Files.readAllBytes(Paths.get("publickey.key")), UTF_8);
        PublicKey publicKey = Util.readPublicKeyFromPem(pkPem);
        if (publicKey == null) {
            return;
        }
        String skPem = new String(Files.readAllBytes(Paths.get("privatekey.key")), UTF_8);
        PrivateKey privateKey = Util.readPrivateKeyFromPem(skPem);
        if (privateKey == null) {
            return;
        }
        System.out.println("pk.len:" + publicKey.getLen());
        System.out.println("pk.N:" + publicKey.getN());
        System.out.println("pk.Nsq:" + publicKey.getNSq());
        System.out.println("pk.G:" + publicKey.getG());
        System.out.println("sk.len:" + privateKey.getLen());
        System.out.println("sk.L:" + privateKey.getL());
        System.out.println("sk.U:" + privateKey.getU());
        System.out.println("sk.Threshold:" + privateKey.getThreshold());

        // STEP2: deserialize public/private key
        String pkHex = "3082010802020400028201006c34ada6fef1d2d6e66a74c8f2416409a1baf19a32fa94eda553a63f929a2259c881e962fe128e1adf4c014c790e5649f5ef3822ed7f1e7ae7163dfe6acad68849ebaa4e0b77f117939b64ffc8d55f500844458fbe587640f0cf4b449f15c0de597a9a0824a35e56e8749bf038f0540a47415db06b183bbbe426521868b6856750f6e37edf1bad3905d8da69f759b1f6cf5ef749de57c20fb565f063415ef8d4c970371e9961f9f7d8d47464ca47ce105cff6e45f988d27c8f5146d996cb8c04e065c9a7b7f8357cd89474d79a081db449af468ed5ac58f06a127f03f9e9457a17df4000d4c5ad5d35e5a064472544446b44d8ad6cbc41bba80e9cdf77f5ba0b";
        byte[] bytes = Hex.decode(pkHex);
        PublicKey pk = Util.deserializePublicKey(bytes);
        if (pk == null) {
            return;
        }
        String skHex = "3082021602020400028201006c34ada6fef1d2d6e66a74c8f2416409a1baf19a32fa94eda553a63f929a2259c881e962fe128e1adf4c014c790e5649f5ef3822ed7f1e7ae7163dfe6acad68849ebaa4e0b77f117939b64ffc8d55f500844458fbe587640f0cf4b449f15c0de597a9a0824a35e56e8749bf038f0540a47415db06b183bbbe426521868b685660261454fab110567e24df7263047f0933b567f7f55d4025a43dd3c50bddf592488a9ba2ade15c392bbb3806cd1a5fa5fe39238e1279262372694dcb0a042939f05c1b0a7dadddfed80cbd981df394c4a9aeedc1f3e9a50ab8f8e6bb2ec93e8d830f01a2b0239d027e1aaf917a2032884c8ae4f81d1a5232c39e319c650f12f70028201006c34ada6fef1d2d6e66a74c8f2416409a1baf19a32fa94eda553a63f929a2259c881e962fe128e1adf4c014c790e5649f5ef3822ed7f1e7ae7163dfe6acad68849ebaa4e0b77f117939b64ffc8d55f500844458fbe587640f0cf4b449f15c0de597a9a0824a35e56e8749bf038f0540a47415db06b183bbbe426521868b6856750f6e37edf1bad3905d8da69f759b1f6cf5ef749de57c20fb565f063415ef8d4c970371e9961f9f7d8d47464ca47ce105cff6e45f988d27c8f5146d996cb8c04e065c9a7b7f8357cd89474d79a081db449af468ed5ac58f06a127f03f9e9457a17df4000d4c5ad5d35e5a064472544446b44d8ad6cbc41bba80e9cdf77f5ba0b02087fffffffffffffff";
        byte[] bytes2 = Hex.decode(skHex);
        PrivateKey sk = Util.deserializePrivateKey(bytes2);
        if (sk == null) {
            return;
        }
        System.out.println("pk.len:" + pk.getLen());
        System.out.println("pk.N:" + pk.getN());
        System.out.println("pk.Nsq:" + pk.getNSq());
        System.out.println("pk.G:" + pk.getG());
        System.out.println("sk.len:" + sk.getLen());
        System.out.println("sk.L:" + sk.getL());
        System.out.println("sk.U:" + sk.getU());
        System.out.println("sk.Threshold:" + sk.getThreshold());

        // STEP3: operate with public/private key
        String eXStr = "218edc06ffe23bc36a44c9fd536aeae3cccb69542c29a38564e3521c7abada90cbff6eb9a0c2e73ab77adb3c3f4f98aec9ff2d2199cec0a8c8813f4e43633d6ed8bbfe778033a63de1a16af1cc8785951907d2ca366c2b0dc482f6ea00db77b832e054a61694e3df018d31617c2e84aeebdde3b155cd489a03111f6bb3605523eae5edf6f72198b3e8a82057065af9d7f01d2353ce75281e79e9db3ece2d8ba67d74088f161abfec24b76a5dd87388813ed67331fff41e1fb983fe9e7b0fbbc3cf774228667a9a6635118e10a9280329912021a03227355daddebd634ffaf4d2228980b69ea76b992b76767879a4de6bc5c162141fb93aa079e8a8e58a3bdf9ce63ea7bdd467109f62c65c7a64c843542180b67805504c5db46c603edaa30ef055648e8a6bca7996163136677bfe4def9705bd4600a22d9ad9e0b2c6f0014c58256dd22b56057201fc05c4eed9da4362f9580e4cab1ab7ff3afb29685051d4af737c8b08972fa2ed7661fe194256d54082e3312252aa1362de32b4cba382b14850cfca9712015f597c53e3259d935bbcf3ec6dcdbf6851c5297f5662654c78f3c47da7507713f04f17388be094fee6d0866e5eb69a68ba3a8cde6a2185f04c0e3a2417a9a8aa9c4d4705502aa0332240d5c9c4f42988c6e0dab039a0a0d072c538045a3874d914c161aea9bc37f1c657203960f5e3fa205fdd4f17d6085a7832";
        String eYStr = "2c1e59e9d20840dfabba795d640bb8e38032b9454e54b6e92476551d43a6d2745d88c763cb61624ead5afa5f06909c3458f23e16f9c599ae8e13b89d33a027d76191e269b19cc3e8c033744810058ef214bd961ad17d3d20303f308cfaf1789b7f164f17dc852b78fbf56c6c78fd557fc32554c211f242da47c50cf3fa2ff091ac67cd527c1ef1fd885927627bbbfa2ba8554d8ed9d6b28ed60f71434e290d00e6061468884de364f51631bf40471d0beb5085d8b9b2a117e641ef6f2fcb238a43cf4449532ada24da1d545e6f37919cb573372861a7016e33490da07a2501372f3dc630b4d7a4d988927e364549ae108f2f6c0da6220023a01a5a1e5191f456fcc3865f6f15f6c302fcba1761f9c402332af299d68be5d641da3a85a19b98f8e5434c1d33c958bf018ee445f7030ed294d13bf54e7b59f63530cc4785921a591c464b339d0cdf8b08f390373be6489eff54dcc6626274407d973dd52756a860b12f9e4e77b4c3c9e2c681e01842126cfb6ffd3356d41d6365f021c7b340c1c534db7b00a21fb13ac6bb82f1006dda7b0e6b72cf5dc7a5ff668a520a953e02baf366b6ab35baabf9b4c7a3d0d7e7841c69ff8a2a387b0f438b899ef80e76aa0d5ddba4a92234000d89551ad1e013055f61fdbe5118895312387722da6d21323d2c99f443c5cfcbb409638f0347fef6925bae804a232e3d35ab845c1b29ef61c9";
        Cipher eXNum = Util.hexStrToCipher(publicKey, eXStr);
        if (eXNum == null) {
            return;
        }
        Cipher eYNum = Util.hexStrToCipher(publicKey, eYStr);
        if (eYNum == null) {
            return;
        }
        BigInteger sum = eXNum.addCipherText(eYNum).decrypt(privateKey);
        System.out.println("sum:" + sum.toString());
    }

}
