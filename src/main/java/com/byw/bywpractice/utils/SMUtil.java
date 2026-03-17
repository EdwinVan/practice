package com.byw.bywpractice.utils;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * 国密算法工具类 (SM2/SM3/SM4)
 * SM2 非对称加密算法      密钥交换/数字签名            安全性高，速度慢
 * SM3 哈希              使用场景：完整性校验          特点：64位十六进制，不可逆
 * SM4 对称加密	        大数据量加密	                速度快，需密钥
 * @author fanyujie
 * @date 2026年03月17日 14:12
 * @return
 */
@Component
public class SMUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ==================== SM3 哈希算法 ====================

    /**
     * SM3 哈希 (仿照 sha256 风格)
     * @param input 输入字符串
     * @return 64位小写十六进制哈希值
     */
    public static String sm3(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", "BC");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("SM3算法不可用", e);
        }
    }

    // ==================== SM4 对称加密算法 ====================

    private static final int SM4_KEY_SIZE = 16;  // 128位

    private static final int SM4_IV_SIZE = 16;   // 128位

    public static final String SM4_KEY = "vMPweHcGTiB/5fWS4lMYyg==";

    public static final String SM4_IV = "an/EX5m5yhrDnO+bAXuxtQ==";

    /**
     * SM4-CBC 加密
     * @param plaintext 明文
     * @param key Base64编码的16字节密钥
     * @param iv Base64编码的16字节IV
     * @return Base64编码的密文
     */
    public static String sm4Encrypt(String plaintext, String key, String iv) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] ivBytes = Base64.getDecoder().decode(iv);

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CBCBlockCipher(new SM4Engine()), new PKCS7Padding());

            CipherParameters params = new ParametersWithIV(
                    new KeyParameter(keyBytes), ivBytes);
            cipher.init(true, params);

            byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] output = new byte[cipher.getOutputSize(input.length)];

            int len = cipher.processBytes(input, 0, input.length, output, 0);
            cipher.doFinal(output, len);

            return Base64.getEncoder().encodeToString(output);
        } catch (Exception e) {
            throw new RuntimeException("SM4加密失败", e);
        }
    }

    /**
     * SM4-CBC 解密
     * @param ciphertext Base64编码的密文
     * @param key Base64编码的16字节密钥
     * @param iv Base64编码的16字节IV
     * @return 明文
     */
    public static String sm4Decrypt(String ciphertext, String key, String iv) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            byte[] encrypted = Base64.getDecoder().decode(ciphertext);

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    new CBCBlockCipher(new SM4Engine()), new PKCS7Padding());

            CipherParameters params = new ParametersWithIV(
                    new KeyParameter(keyBytes), ivBytes);
            cipher.init(false, params);

            byte[] output = new byte[cipher.getOutputSize(encrypted.length)];
            int len = cipher.processBytes(encrypted, 0, encrypted.length, output, 0);
            len += cipher.doFinal(output, len);

            return new String(output, 0, len, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("SM4解密失败", e);
        }
    }

    /**
     * 生成SM4密钥 (Base64)
     */
    public static String generateSm4Key() {
        byte[] key = new byte[SM4_KEY_SIZE];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * 生成SM4 IV (Base64)
     */
    public static String generateSm4Iv() {
        byte[] iv = new byte[SM4_IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    // ==================== SM2 非对称加密算法 ====================

    public static final String SM2_PUBLIC_KEY = "BOpBVOK8O4XjKExOlq0cdtW/9CGJg7AUI5x98Iq2tOjGgJYQx3X+GqDLPVkvKIaYlIdEFMthHNSlbHZaflggfQo=";

    public static final String SM2_PRIVATE_KEY = "cwjFQPnmegkWZ/8I+sQl72UObQz1wWe4BwWfYAuVIPg=";

    /**
     * SM2 密钥对
     */
    public static class SM2KeyPair {
        private final String privateKey;  // Base64
        private final String publicKey;   // Base64

        public SM2KeyPair(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public String getPrivateKey() { return privateKey; }
        public String getPublicKey() { return publicKey; }
    }

    /**
     * 生成SM2密钥对
     */
    public static SM2KeyPair generateSm2KeyPair() {
        try {
            X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
            ECDomainParameters domainParams = new ECDomainParameters(
                    sm2ECParameters.getCurve(), sm2ECParameters.getG(),
                    sm2ECParameters.getN(), sm2ECParameters.getH());

            SecureRandom random = new SecureRandom();
            BigInteger d = new BigInteger(256, random).mod(domainParams.getN().subtract(BigInteger.ONE)).add(BigInteger.ONE);

            ECPoint Q = domainParams.getG().multiply(d);

            String privateKey = Base64.getEncoder().encodeToString(d.toByteArray());
            String publicKey = Base64.getEncoder().encodeToString(Q.getEncoded(false));

            return new SM2KeyPair(privateKey, publicKey);
        } catch (Exception e) {
            throw new RuntimeException("SM2密钥生成失败", e);
        }
    }

    /**
     * SM2 加密
     * @param plaintext 明文
     * @param publicKey Base64编码的公钥
     * @return Base64编码的密文
     */
    public static String sm2Encrypt(String plaintext, String publicKey) {
        try {
            byte[] pubKeyBytes = Base64.getDecoder().decode(publicKey);

            X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
            ECDomainParameters domainParams = new ECDomainParameters(
                    sm2ECParameters.getCurve(), sm2ECParameters.getG(),
                    sm2ECParameters.getN(), sm2ECParameters.getH());

            ECPoint pubPoint = sm2ECParameters.getCurve().decodePoint(pubKeyBytes);
            ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(pubPoint, domainParams);

            SM2Engine engine = new SM2Engine();
            engine.init(true, new ParametersWithRandom(pubKeyParams, new SecureRandom()));

            byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = engine.processBlock(input, 0, input.length);

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("SM2加密失败", e);
        }
    }

    /**
     * SM2 解密
     * @param ciphertext Base64编码的密文
     * @param privateKey Base64编码的私钥
     * @return 明文
     */
    public static String sm2Decrypt(String ciphertext, String privateKey) {
        try {
            byte[] priKeyBytes = Base64.getDecoder().decode(privateKey);
            byte[] encrypted = Base64.getDecoder().decode(ciphertext);

            X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
            ECDomainParameters domainParams = new ECDomainParameters(
                    sm2ECParameters.getCurve(), sm2ECParameters.getG(),
                    sm2ECParameters.getN(), sm2ECParameters.getH());

            BigInteger d = new BigInteger(1, priKeyBytes);
            ECPrivateKeyParameters priKeyParams = new ECPrivateKeyParameters(d, domainParams);

            SM2Engine engine = new SM2Engine();
            engine.init(false, priKeyParams);

            byte[] decrypted = engine.processBlock(encrypted, 0, encrypted.length);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("SM2解密失败", e);
        }
    }

    // ==================== 工具方法 ====================

    /**
     * 字节数组转十六进制字符串 (仿照你原有的风格)
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
