package com.byw.bywpractice.model.req;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * 加密解密明文
 * @author fanyujie
 * @date 2026年03月17日 14:42
 * @return
 */
@Data
public class PlaintextReq {

    @Schema(description  = "明文")
    private String ciphertext;
}
