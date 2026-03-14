package com.byw.bywpractice;

import com.byw.bywpractice.config.AppConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class BywPracticeApplication {
    @Autowired
    private static AppConfig appConfig;

    public static void main(String[] args) {
        // 先启动 Spring 应用，获取上下文
        ConfigurableApplicationContext context = SpringApplication.run(BywPracticeApplication.class, args);

        // 从上下文中获取 Bean
        AppConfig appConfig = context.getBean(AppConfig.class);

        System.out.println("========== 启动成功 ==========");
        int port = appConfig.getServerPort();
        System.out.println("应用名称: " + appConfig.getAppName());
        System.out.println("访问地址: http://localhost:" + port);
    }

}
