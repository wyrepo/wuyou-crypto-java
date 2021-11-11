package com.wuyou.crypto.paillier;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PublicKey;
import com.wuyou.crypto.paillier.num.Cipher;
import com.wuyou.crypto.paillier.util.Util;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PaillierTest {

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
        System.out.println("pk.len:" + publicKey.getLen()); // 1024

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
        System.out.println("pk.len:" + pk.getLen()); // 1024

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
        System.out.println("pk.len:" + sk.getPublicKey().getLen()); // 1024
    }

    @Test
    public void testKeyWriteAndRead() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println("pk.len:" + publicKey.getLen()); // 1024

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
        System.out.println("pk.len:" + pk.getLen()); // 1024

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
        System.out.println("pk.len:" + sk.getPublicKey().getLen()); // 1024
    }


    @Test
    public void testPaillierOps() throws Exception {
        // paillier add/sub/mul/div
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println("pk.len:" + publicKey.getLen()); // 1024

        Cipher eX, eY;
        BigInteger x = new BigInteger("100");
        BigInteger y = new BigInteger("-23");

        // add ciphertext
        eX = new Cipher(x, publicKey);
        eY = new Cipher(y, publicKey);
        BigInteger sum = eX.addCipherText(eY).decrypt(privateKey);
        System.out.println("add ciphertext:" + sum);

        // sub ciphertext
        eX = new Cipher(x, publicKey);
        eY = new Cipher(y, publicKey);
        BigInteger diff = eX.subCipherText(eY).decrypt(privateKey);
        System.out.println("sub ciphertext:" + diff);

        // add plaintext
        eX = new Cipher(x, publicKey);
        BigInteger sum2 = eX.addPlainText(y).decrypt(privateKey);
        System.out.println("add plaintext:" + sum2);

        // mul plaintext
        eX = new Cipher(x, publicKey);
        BigInteger prod = eX.mulPlainText(y).decrypt(privateKey);
        System.out.println("mul plaintext:" + prod);

        // div plaintext
        eX = new Cipher(x, publicKey);
        BigInteger quotient = eX.divPlainText(y).decrypt(privateKey); // must be "x mod y == 0", avoid overflowing
        System.out.println("div plaintext:" + quotient);
    }

}
