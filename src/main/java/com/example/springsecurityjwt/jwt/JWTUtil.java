package com.example.springsecurityjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // JWT 서명 서명 및 검증에 사용할 SecretKey 객체
    private final SecretKey secretKey;

    // 생성자에서 비밀키를 문자열에서 SecretKey 객체로 변환하여 초기화
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {

        // 비밀키 문자열을 SecretKeySpec 객체로 변환하여 사용
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 토큰에서 "username" 클레임 값을 추출
    public String getUsername(String token) {

        return Jwts.parser()
                .verifyWith(secretKey) // 비밀키를 사용하여 토큰의 서명 검증
                .build() // 파서 생성
                .parseSignedClaims(token) // 서명된 클레임을 포함하는 JWT 파싱
                .getPayload() // 페이로드 부분 추출
                .get("username", String.class); // "username" 클레임 값 반환
    }

    // 토큰에서 "role" 클레임 값을 추출
    public String getRole(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }

    // 토큰에서 "category" 클레임 값을 추출
    public String getCategory(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("category", String.class);
    }

    // 토큰의 만료 여부를 확인
    public Boolean isExpired(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date()); // 현재 시간보다 더 이전이면 만료이므로 true 를 반환
    }

    // 새로운 JWT 토큰을 생성
    public String createJwt(String category, String username, String role, Long expired) {

        return Jwts.builder()
                .claim("category", category)
                .claim("username", username) // "username" 클레임 추가
                .claim("role", role) // "role" 클레임 추가
                .issuedAt(new Date(System.currentTimeMillis())) // 발급 시간 설정
                .expiration(new Date(System.currentTimeMillis() + expired)) // 만료 시간 설정
                .signWith(secretKey) // 비밀키를 사용하여 서명 추가
                .compact(); // 토큰을 인코딩 및 직렬화
    }
}
