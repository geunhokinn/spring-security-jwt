package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.jwt.JWTFilter;
import com.example.springsecurityjwt.jwt.JWTUtil;
import com.example.springsecurityjwt.jwt.LoginFilter;
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

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // LoginFilter 의 AuthenticationManager 가 인자로 받을 AuthenticationConfiguration 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    // LoginFilter 가 인자로 받을 JWTUtil 주입
    private final JWTUtil jwtUtil;

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
                .csrf((auth) -> auth.disable()); // Disable CSRF

        http
                .formLogin((auth) -> auth.disable()); // Disable Form-based login

        http
                .httpBasic((auth) -> auth.disable()); // Disable HTTP Basic authentication

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()); // Authorization by path

        // LoginFilter 앞에 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        // UsernamePasswordAuthenticationFilter 자리를 대체
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // Session settings

        return http.build();
    }
}
