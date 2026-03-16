package com.byw.bywpractice.controller;

import com.byw.bywpractice.service.EncryptService;
import com.byw.bywpractice.utils.SecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 加密解密接口
 * @author fanyujie
 * @date 2026年03月14日 15:02
 * @return
 */

@RestController
@RequestMapping("/api")
public class EncryptController {

    @Autowired
    private EncryptService encryptService;

    @PostMapping("/aesEncrypt")
    public String aesEncrypt(String plaintext) {
        return SecurityUtil.aesEncrypt(plaintext, SecurityUtil.generateAesKey());
    }

    @PostMapping("/aesDecrypt")
    public String aesDecrypt(String ciphertext) {
        return SecurityUtil.aesDecrypt(ciphertext, SecurityUtil.AES_KEY);
    }

    @PostMapping("/rsaEncrypt")
    public String rsaEncrypt(String plaintext) {
        return SecurityUtil.rsaEncrypt(plaintext, SecurityUtil.RSA_PUBLIC_KEY);
    }

    @PostMapping("/rsaDecrypt")
    public String rsaDecrypt(String ciphertext) {
        return SecurityUtil.rsaDecrypt(ciphertext, SecurityUtil.RSA_PRIVATE_KEY);
    }
}
