package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.jwt.JWTFilter;
import com.example.springsecurityjwt.jwt.JWTUtil;
import com.example.springsecurityjwt.jwt.LoginFilter;
import com.example.springsecurityjwt.repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // LoginFilter 의 AuthenticationManager 가 인자로 받을 AuthenticationConfiguration 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    // LoginFilter 가 인자로 받을 JWTUtil 주입
    private final JWTUtil jwtUtil;

    // LoginFilter 가 인자로 받을 RefreshRepository 주입
    private final RefreshRepository refreshRepository;

    @Bean // AuthenticationManager Bean 등록
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean // Password encryption
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {

                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                                CorsConfiguration corsConfiguration = new CorsConfiguration();

                                // 허용할 클라이언트의 도메인을 설정
                                corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                                // 클라이언트 요청에서 허용할 HTTP 메서드를 설정
                                corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                                // 클라이언트 요청에서 인증 정보 전달 허용
                                corsConfiguration.setAllowCredentials(true);
                                // 클라이언트 요청에서 허용할 헤더를 설정
                                corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                                // CORS 설정이 브라우저에서 캐시되는 시간 설정
                                corsConfiguration.setMaxAge(3600L);

                                // 서버에서 클라이언트로 허용할 응답 헤더를 설정합니다.
                                corsConfiguration.setExposedHeaders(Collections.singletonList("Authorization"));

                                return corsConfiguration;
                            }
                        }));

        http
                .csrf((auth) -> auth.disable()); // Disable CSRF

        http
                .formLogin((auth) -> auth.disable()); // Disable Form-based login

        http
                .httpBasic((auth) -> auth.disable()); // Disable HTTP Basic authentication

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("reissue").permitAll()
                        .anyRequest().authenticated()); // Authorization by path

        // LoginFilter 앞에 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        // UsernamePasswordAuthenticationFilter 자리를 대체
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshRepository), UsernamePasswordAuthenticationFilter.class);

        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // Session settings

        return http.build();
    }
}
