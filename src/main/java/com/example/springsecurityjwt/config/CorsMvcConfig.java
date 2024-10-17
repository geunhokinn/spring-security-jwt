package com.example.springsecurityjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        // 모든 엔드포인트에 대해 CORS 허용 설정
        corsRegistry.addMapping("/**")
                // 허용할 origin 설정
                .allowedOrigins("http://localhost:3000");
    }
}
