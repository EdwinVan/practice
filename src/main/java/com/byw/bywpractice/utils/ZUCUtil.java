package com.byw.bywpractice.utils;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * ZUC (祖冲之) 算法工具类
 * ZUC-128 流密码算法 - 中国自主研发的流密码标准
 * 密钥长度：128位 (16字节)
 * IV长度：128位 (16字节)
 * @author fanyujie
 * @date 2026年03月18日
 */
@Component
public class ZUCUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ==================== 常量定义 ====================

    private static final int ZUC_KEY_SIZE = 16;  // 128位
    private static final int ZUC_IV_SIZE = 16;   // 128位

    public static final String ZUC_KEY = "/WNJSI1b11KcPlqvlVBsHA==";
    public static final String ZUC_IV = "R1SkJsgQsWOHAxycfpFJ/g==";

    // ==================== ZUC 加密 ====================

    /**
     * ZUC-128 流密码加密
     * @param plaintext 明文
     * @param key Base64编码的16字节密钥
     * @param iv Base64编码的16字节IV
     * @return Base64编码的密文
     */
    public static String zucEncrypt(String plaintext, String key, String iv) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] ivBytes = Base64.getDecoder().decode(iv);

            StreamCipher cipher = new Zuc128Engine();
            KeyParameter keyParam = new KeyParameter(keyBytes);
            ParametersWithIV params = new ParametersWithIV(keyParam, ivBytes);

            cipher.init(true, params);

            byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] output = new byte[input.length];

            cipher.processBytes(input, 0, input.length, output, 0);

            return Base64.getEncoder().encodeToString(output);
        } catch (Exception e) {
            throw new RuntimeException("ZUC加密失败", e);
        }
    }

    /**
     * ZUC-128 流密码解密
     * @param ciphertext Base64编码的密文
     * @param key Base64编码的16字节密钥
     * @param iv Base64编码的16字节IV
     * @return 明文
     */
    public static String zucDecrypt(String ciphertext, String key, String iv) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            byte[] encrypted = Base64.getDecoder().decode(ciphertext);

            StreamCipher cipher = new Zuc128Engine();
            KeyParameter keyParam = new KeyParameter(keyBytes);
            ParametersWithIV params = new ParametersWithIV(keyParam, ivBytes);

            cipher.init(false, params);

            byte[] output = new byte[encrypted.length];
            cipher.processBytes(encrypted, 0, encrypted.length, output, 0);

            return new String(output, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("ZUC解密失败", e);
        }
    }

    // ==================== 简化版（使用默认密钥和IV） ====================

    /**
     * ZUC-128 加密（使用默认密钥和IV）
     * @param plaintext 明文
     * @return Base64编码的密文
     */
    public static String zucEncrypt(String plaintext) {
        return zucEncrypt(plaintext, ZUC_KEY, ZUC_IV);
    }

    /**
     * ZUC-128 解密（使用默认密钥和IV）
     * @param ciphertext Base64编码的密文
     * @return 明文
     */
    public static String zucDecrypt(String ciphertext) {
        return zucDecrypt(ciphertext, ZUC_KEY, ZUC_IV);
    }

    // ==================== 密钥生成 ====================

    /**
     * 生成ZUC密钥 (Base64)
     * @return Base64编码的128位密钥
     */
    public static String generateZucKey() {
        byte[] key = new byte[ZUC_KEY_SIZE];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    /**
     * 生成ZUC IV (Base64)
     * @return Base64编码的128位IV
     */
    public static String generateZucIv() {
        byte[] iv = new byte[ZUC_IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * 生成ZUC密钥对 (密钥 + IV)
     * @return String[0]=Base64密钥, String[1]=Base64 IV
     */
    public static String[] generateZucKeyPair() {
        return new String[]{generateZucKey(), generateZucIv()};
    }
}
