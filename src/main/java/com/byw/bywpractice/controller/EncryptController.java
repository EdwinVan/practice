package com.byw.bywpractice.controller;

import com.byw.bywpractice.model.req.PlaintextReq;
import com.byw.bywpractice.utils.SMUtil;
import com.byw.bywpractice.utils.SecurityUtil;
import com.byw.bywpractice.utils.ZUCUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

/**
 * 加密解密接口管理
 * @author fanyujie
 * @date 2026年03月14日 15:02
 * @return
 */
@Tag(name = "加密解密接口管理")
@RestController
@RequestMapping("/api")
@Slf4j
public class EncryptController {

    @Operation(summary = "AES加密")
    @PostMapping("/aesEncrypt")
    public String aesEncrypt(@RequestParam String plaintext) {
        return SecurityUtil.aesEncrypt(plaintext, SecurityUtil.AES_KEY);
    }

    @Operation(summary = "AES解密")
    @PostMapping("/aesDecrypt")
    public String aesDecrypt(@RequestParam String ciphertext) {
        return SecurityUtil.aesDecrypt(ciphertext, SecurityUtil.AES_KEY);
    }

    @Operation(summary = "RSA加密")
    @PostMapping("/rsaEncrypt")
    public String rsaEncrypt(@RequestParam String plaintext) {
        return SecurityUtil.rsaEncrypt(plaintext, SecurityUtil.RSA_PUBLIC_KEY);
    }

    @Operation(summary = "RSA解密")
    @PostMapping("/rsaDecrypt")
    public String rsaDecrypt(@RequestParam String ciphertext) {
        return SecurityUtil.rsaDecrypt(ciphertext, SecurityUtil.RSA_PRIVATE_KEY);
    }

    @Operation(summary = "SM3哈希编码")
    @PostMapping("/sm3")
    public String sm3(@RequestParam String plaintext) {
        return SMUtil.sm3(plaintext);
    }

    @Operation(summary = "SM4加密")
    @PostMapping("/sm4Encrypt")
    public String sm4Encrypt(@RequestParam String plaintext) {
        return SMUtil.sm4Encrypt(plaintext, SMUtil.SM4_KEY, SMUtil.SM4_IV);
    }

    @Operation(summary = "SM4解密")
    @PostMapping("/sm4Decrypt")
    public String sm4Decrypt(@RequestParam String plaintext) {
        return SMUtil.sm4Decrypt(plaintext, SMUtil.SM4_KEY, SMUtil.SM4_IV);
    }

    @Operation(summary = "SM2加密")
    @PostMapping("/sm2Encrypt")
    public String sm2Encrypt(@RequestBody PlaintextReq plaintextReq) {
        return SMUtil.sm2Encrypt(plaintextReq.getCiphertext(), SMUtil.SM2_PUBLIC_KEY);
    }

    @Operation(summary = "SM2解密")
    @PostMapping("/sm2Decrypt")
    public String sm2Decrypt(@RequestBody PlaintextReq plaintextReq) {
        return SMUtil.sm2Decrypt(plaintextReq.getCiphertext(), SMUtil.SM2_PRIVATE_KEY);
    }

    @Operation(summary = "DES加密")
    @PostMapping("/desEncrypt")
    public String desEncrypt(@RequestBody PlaintextReq plaintextReq) {
        return SecurityUtil.desEncrypt(plaintextReq.getCiphertext());
    }

    @Operation(summary = "DES解密")
    @PostMapping("/desDecrypt")
    public String desDecrypt(@RequestBody PlaintextReq plaintextReq) {
        return SecurityUtil.desDecrypt(plaintextReq.getCiphertext());
    }

    @Operation(summary = "ZUC加密")
    @PostMapping("/zucEncrypt")
    public String zucEncrypt(@RequestBody PlaintextReq plaintextReq) {
        return ZUCUtil.zucEncrypt(plaintextReq.getCiphertext());
    }

    @Operation(summary = "ZUC解密")
    @PostMapping("/zucDecrypt")
    public String zucDecrypt(@RequestBody PlaintextReq plaintextReq) {
        return ZUCUtil.zucDecrypt(plaintextReq.getCiphertext());
    }
}
