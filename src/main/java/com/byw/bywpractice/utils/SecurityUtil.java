package com.byw.bywpractice.utils;

import com.byw.bywpractice.model.req.GetTokenReq;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;


/**
 * 加密解密工具类
 * 支持 AES-256-GCM 对称加密和 RSA-2048 非对称加密
 * @author fanyujie
 * @date 2026年03月14日 15:10
 */
@Component
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
    /** RSA 签名算法 */
    private static final String ALGORITHM = "RSA";
    /** AES 密钥 */
    public static final String AES_KEY = "bgq9AZ915Ryr+1TmxFqhfxPVn2xHMNp5sXHR88uedk8=";
    /** RSA 公钥 */
    public static final String RSA_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWuyJiccenbkhYAIlyltCpkKLeJJ4s9HaAiELqfSWfmM18AbkVUBQn44rWRJuZ1xFjDTNAtc4zoz8Y16zPfvK0JNqjOzrRiuOlh3A+MkBOXJybxfQhCAcgy8yf5t2Jg0tlzf4ZYMmopE12qxLX9HYc8rAm5cub7uDcyYOyug6b8ZIfpXrkeMrQUVJ2rYSmvYKRChohaeyr0AbO+pY6wzb4z57kLZzW6dUSZzGn59iPNccqq8t3QCdyjZxI37UeKEyhe10zQ2EI6OR/FnsKgCvBXD28mN5o3a5NA1EUbKK4wwuVL07TifUI9Lj7gq8+tBgoecopqu8zrKrsOj1rgjtQIDAQAB";
    /** RSA 私钥 */
    public static final String RSA_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCta7ImJxx6duSFgAiXKW0KmQot4kniz0doCIQup9JZ+YzXwBuRVQFCfjitZEm5nXEWMNM0C1zjOjPxjXrM9+8rQk2qM7OtGK46WHcD4yQE5cnJvF9CEIByDLzJ/m3YmDS2XN/hlgyaikTXarEtf0dhzysCbly5vu4NzJg7K6Dpvxkh+leuR4ytBRUnathKa9gpEKGiFp7KvQBs76ljrDNvjPnuQtnNbp1RJnMafn2I81xyqry3dAJ3KNnEjftR4oTKF7XTNDYQjo5H8WewqAK8FcPbyY3mjdrk0DURRsorjDC5UvTtOJ9Qj0uPuCrz60GCh5yimq7zOsquw6PWuCO1AgMBAAECggEABiMXypxbOGVBOI07oJfVdUjNsKp/qWBi+0ZD4T/MpKT9bDwu7ZF3yjHb0R0Js+EjuaCQNNkLGDp80JlMZXkHtHzz8ShDvUYwkj2DtrZA1dCI99Pr/hNF7GNRggd4PTBDu0llnd7YwtZOUd5Dd2P383jooX0k2GjulTvujjeAygzLeah7rHZmKWDAZrPtX2lCZ7rGr8ryESwArDzObpkpJtxRaFuQhfb4eXN0mhWs4NoCswrQ7LqntOY/hMCRGKI6KryZeUGxg9pm61TRQ/VV2GB8eQIz2xeBMjoE0ElCk/ImbRg6wnnlOUkZZ/X6wWJ72SfxluUsPnGfO/imJQflCQKBgQDpipocw3PpmUuvbQeJkj4JdAerzjOMm633vhvOUI1JqY9kCf70HQjtB8rsQjpzE7RhaTp8OlRQrRatFwFHSb4lVXlNKaZw1UhLPOBNCXIOo+gKP6HJkkyIvF4SZt/+u3CwELqQn+q5zo+QIwEsTMUjia1SmsqBHe9yJb+JIWL12QKBgQC+GQW8l8HhMNGtiR8406YridQf9TUSViAwCN9tT9HeGSpl4mROmj0viU2c6p0RGv6fho2W1DSJMN4qsOgkg9fKciInAHXCoejuxQEWmAW2F6UzcWsyX6PGsbxHcaFWxUS3WkpsjsxJqHxw4jMtMXwFyIdr6FNn9pa+YOfViPunPQKBgECbOTsPzvcmk0t6bAVg0Yyn7p9WsegKATxx+RtAKXXhVGumYEOD7L4106s8PxMqtlHkXGuVb1HKMGW94XqpKdMGLEJubT71ocQ+mQZ2wHjQWxbKt6UdtdJ12chZcUn07J2oYxQzSSoRvKFxLZflvPux0KLzc2X4tA7t5mi3NbsxAoGAI36umIlJlU+1Rw7cepLiayzAI/t4HmVgezec6F9IE41lYkLEcfzQweiESnFwRHpi4syP8YLMEHXEdfo0TmUjzNRE1j16v43V3YeBbYOTRW3i1dkup+g9v2L+geSQuI/7BbVhQiXjtTk1iyphXeXof3fy+U4XDMl5WjDj+PYr7w0CgYEAjCeDaF5GphJo8VzwNCGU3+wGs1MHfSph3qg7B4VSfONoUu+aROdVWF+2rggAHr5a5rYJQnM+RE6TObdaAJDo0sXOmD7DzyZD55UZvMb6P4Lcqm4c5FI3TQbc8kFbJETD/XS45FFXJ9TsvAqB8XRv/ywet8N7F6nimeRDfAdhVBU=";

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
            // 清理公钥中的空白字符
            publicKey = publicKey.replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(spec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // 返回纯 Base64，无换行
            return Base64.getEncoder().encodeToString(encrypted);

        } catch (IllegalArgumentException e) {
            throw new RuntimeException("公钥Base64解码失败，请检查密钥格式", e);
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
            // 清理私钥中的空白字符
            privateKey = privateKey.replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyFactory.generatePrivate(spec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, priKey);

            // 修复密文：URL空格转+，再清理所有空白
            ciphertext = ciphertext.replace(' ', '+')
                    .replaceAll("\\s+", "");

            // 自动修复缺失的Base64填充
            int mod = ciphertext.length() % 4;
            if (mod != 0) {
                ciphertext += "=".repeat(4 - mod);
            }

            byte[] encrypted = Base64.getDecoder().decode(ciphertext);
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Base64解码失败: " + e.getMessage() +
                    ", 密文长度=" + ciphertext.length(), e);
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
            KeyPairGenerator generator;
            try {
                generator = KeyPairGenerator.getInstance(ALGORITHM, "BC");
            } catch (NoSuchProviderException e) {
                generator = KeyPairGenerator.getInstance(ALGORITHM);
            }

            generator.initialize(RSA_KEY_SIZE, new SecureRandom());
            KeyPair keyPair = generator.generateKeyPair();

            String publicKey = Base64.getEncoder().encodeToString(
                    keyPair.getPublic().getEncoded()
            );
            String privateKey = Base64.getEncoder().encodeToString(
                    keyPair.getPrivate().getEncoded()
            );

            return new String[]{publicKey, privateKey};

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("当前 Java 环境不支持 RSA 算法", e);
        }
    }

    // ==================== RSA辅助方法 ====================

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

    // ==================== hash加密 ====================
    /**
     * MD5 哈希（不推荐用于安全场景，仅用于兼容性）
     * @param input 输入字符串
     * @return 32位小写十六进制哈希值
     */
    public static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5算法不可用", e);
        }
    }

    /**
     * SHA-256 哈希
     * @param input 输入字符串
     * @return 64位小写十六进制哈希值
     */
    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256算法不可用", e);
        }
    }

    /**
     * SHA-512 哈希
     * @param input 输入字符串
     * @return 128位小写十六进制哈希值
     */
    public static String sha512(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512算法不可用", e);
        }
    }

    /**
     * 加盐 SHA-256 哈希（推荐用于密码存储）
     * @param input 输入字符串
     * @param salt 盐值
     * @return 加盐后的哈希值
     */
    public static String sha256WithSalt(String input, String salt) {
        return sha256(input + salt);
    }

    /**
     * HMAC-SHA256（带密钥的哈希，用于完整性校验）
     * @param data 原始数据
     * @param key 密钥
     * @return Base64编码的HMAC值
     */
    public static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hmac);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256计算失败", e);
        }
    }

    /**
     * PBKDF2 密码哈希（业界标准，适合存储密码）
     * @param password 密码
     * @param salt 盐值
     * @return Base64编码的哈希值
     */
    public static String pbkdf2Hash(String password, String salt) {
        try {
            int iterations = 10000;
            int keyLength = 256;

            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt.getBytes(StandardCharsets.UTF_8),
                    iterations,
                    keyLength
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2哈希失败", e);
        }
    }

    /**
     * 生成随机盐值
     * @param length 盐值长度（字节）
     * @return Base64编码的盐值
     */
    public static String generateSalt(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * 字节数组转十六进制字符串
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ==================== 测试方法 ====================

    public static void main(String[] args) throws JsonProcessingException {
        // hash256加密
        String pid = "1003611070107007052";
        String secret = "e4f9828e7af8e44f3af3de93fff901b6";
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(SerializationFeature.INDENT_OUTPUT);
        GetTokenReq req = new GetTokenReq();
        req.setGrant_type("client_credentials");
        String data = mapper.writeValueAsString(req);
        String text = pid + secret + timestamp + data;
        String textHash = sha256(text);
        System.out.println("hash256加密后: " + textHash);
    }
}