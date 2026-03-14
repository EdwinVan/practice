package com.byw.bywpractice.config;

/**
 *
 * @author fanyujie
 * @date 2026年03月14日 17:18
 * @return
 */
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Data
@Component
public class AppConfig {

    @Value("${spring.application.name}")
    private String appName;

    @Value("${server.port}")
    private int serverPort;
}