package com.byw.bywpractice.model.req;

import lombok.Data;
import org.springframework.stereotype.Component;

/**
 *
 * @author fanyujie
 * @date 2026年03月17日 9:32
 * @return
 */
@Data
@Component
public class GetTokenReq {

    private String grant_type;

}
