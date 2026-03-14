package com.byw.bywpractice.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;


/**
 * 加密解密工具类
 * 支持 AES-256-GCM 对称加密和 RSA-2048 非对称加密
 * @author fanyujie
 * @date 2026年03月14日 15:10
 */
public class SecurityUtil {

    // ==================== 常量定义 ====================

    /** AES 密钥长度 (256位) */
    private static final int AES_KEY_SIZE = 256;
    /** AES GCM 初始化向量长度 (96位) */
    private static final int AES_GCM_IV_LENGTH = 12;
    /** AES GCM 认证标签长度 (128位) */
    private static final int AES_GCM_TAG_LENGTH = 128;
    /** RSA 密钥长度 (2048位) */
    private static final int RSA_KEY_SIZE = 2048;

    /** AES 密钥 */
    public static final String AES_KEY = "6JavIyzhU7hTQxycg14qcbWqD0Qu2tIa6m+s5knttMo=";


    // ==================== AES 对称加密 ====================

    /**
     * AES-GCM 加密
     * @param plaintext 明文
     * @param key Base64编码的密钥
     * @return Base64编码的密文(IV + ciphertext + authTag)
     */
    public static String aesEncrypt(String plaintext, String key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            byte[] iv = new byte[AES_GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);

        } catch (Exception e) {
            throw new RuntimeException("AES加密失败", e);
        }
    }

    /**
     * AES-GCM 解密
     * @param ciphertext Base64编码的密文(IV + ciphertext + authTag)
     * @param key Base64编码的密钥
     * @return 明文
     */
    public static String aesDecrypt(String ciphertext, String key) {
        try {
            // 解码密钥
            byte[] keyBytes = Base64.getDecoder().decode(key);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            // 解码密文
            byte[] combined = Base64.getDecoder().decode(ciphertext);

            // 分离IV和密文
            byte[] iv = new byte[AES_GCM_IV_LENGTH];
            byte[] encrypted = new byte[combined.length - AES_GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

            // 初始化Cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

            // 解密
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("AES解密失败", e);
        }
    }

    /**
     * 生成AES密钥
     * @return Base64编码的256位密钥
     */
    public static String generateAesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            System.out.println("AES密钥：" + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("生成AES密钥失败", e);
        }
    }

    // ==================== RSA 非对称加密 ====================

    /**
     * RSA 公钥加密
     * @param plaintext 明文
     * @param publicKey Base64编码的公钥
     * @return Base64编码的密文
     */
    public static String rsaEncrypt(String plaintext, String publicKey) {
        try {
            // 解码公钥
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(spec);

            // 加密
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(encrypted);

        } catch (Exception e) {
            throw new RuntimeException("RSA加密失败", e);
        }
    }

    /**
     * RSA 私钥解密
     * @param ciphertext Base64编码的密文
     * @param privateKey Base64编码的私钥
     * @return 明文
     */
    public static String rsaDecrypt(String ciphertext, String privateKey) {
        try {
            // 解码私钥
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyFactory.generatePrivate(spec);

            // 解密
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            byte[] encrypted = Base64.getDecoder().decode(ciphertext);
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("RSA解密失败", e);
        }
    }

    /**
     * 生成RSA密钥对
     * @return String[0]=Base64公钥, String[1]=Base64私钥
     */
    public static String[] generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(RSA_KEY_SIZE, new SecureRandom());
            KeyPair keyPair = generator.generateKeyPair();

            String publicKey = Base64.getEncoder().encodeToString(
                    keyPair.getPublic().getEncoded()
            );
            String privateKey = Base64.getEncoder().encodeToString(
                    keyPair.getPrivate().getEncoded()
            );

            System.out.println("生成的RSA：" + publicKey + "0——————————0" + privateKey);
            return new String[]{publicKey, privateKey};
        } catch (Exception e) {
            throw new RuntimeException("生成密钥对失败", e);
        }
    }

    // ==================== 辅助方法 ====================

    /**
     * RSA 私钥签名
     * @param data 待签名数据
     * @param privateKey Base64编码的私钥
     * @return Base64编码的签名
     */
    public static String rsaSign(String data, String privateKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyFactory.generatePrivate(spec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(priKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("RSA签名失败", e);
        }
    }

    /**
     * RSA 公钥验签
     * @param data 原始数据
     * @param sign Base64编码的签名
     * @param publicKey Base64编码的公钥
     * @return 验签结果
     */
    public static boolean rsaVerify(String data, String sign, String publicKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(spec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(pubKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));

            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            throw new RuntimeException("RSA验签失败", e);
        }
    }

    // ==================== 测试方法 ====================

    public static void main(String[] args) {
        System.out.println("========== AES 测试 ==========");
        // 生成AES密钥
        String aesKey = generateAesKey();
        System.out.println("AES密钥: " + aesKey);

        String originalText = "Hello, 这是一个AES加密测试！";
        System.out.println("原始文本: " + originalText);

        // 加密
        String aesEncrypted = aesEncrypt(originalText, aesKey);
        System.out.println("AES加密后: " + aesEncrypted);

        // 解密
        String aesDecrypted = aesDecrypt(aesEncrypted, aesKey);
        System.out.println("AES解密后: " + aesDecrypted);
        System.out.println("AES验证: " + originalText.equals(aesDecrypted));

        System.out.println("\n========== RSA 测试 ==========");
        // 生成RSA密钥对
        String[] keyPair = generateRsaKeyPair();
        String rsaPublicKey = keyPair[0];
        String rsaPrivateKey = keyPair[1];
        System.out.println("RSA公钥: " + rsaPublicKey.substring(0, 50) + "...");
        System.out.println("RSA私钥: " + rsaPrivateKey.substring(0, 50) + "...");

        String rsaOriginal = "Hello, 这是一个RSA加密测试！";
        System.out.println("原始文本: " + rsaOriginal);

        // 加密
        String rsaEncrypted = rsaEncrypt(rsaOriginal, rsaPublicKey);
        System.out.println("RSA加密后: " + rsaEncrypted);

        // 解密
        String rsaDecrypted = rsaDecrypt(rsaEncrypted, rsaPrivateKey);
        System.out.println("RSA解密后: " + rsaDecrypted);
        System.out.println("RSA验证: " + rsaOriginal.equals(rsaDecrypted));

        System.out.println("\n========== RSA 签名测试 ==========");
        // 签名
        String signature = rsaSign(rsaOriginal, rsaPrivateKey);
        System.out.println("签名: " + signature);

        // 验签
        boolean verify = rsaVerify(rsaOriginal, signature, rsaPublicKey);
        System.out.println("验签结果: " + verify);
    }
}