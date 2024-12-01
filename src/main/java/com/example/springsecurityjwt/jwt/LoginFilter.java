package com.example.springsecurityjwt.jwt;

import com.example.springsecurityjwt.dto.CustomUserDetails;
import com.example.springsecurityjwt.dto.LoginDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // 로그인 검증을 위해 AuthenticationManager 주입
    private final AuthenticationManager authenticationManager;
    // 토큰을 발급받기 위해 JWTUtil 주입
    private final JWTUtil jwtUtil;

    // form login 을 disable 했기 때문에 직접 구현
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 클라이언트 요청에서 username, password 추출
//        String username = obtainUsername(request);
//        String password = obtainPassword(request);

        // json method
        LoginDTO loginDTO;

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = request.getInputStream();
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            loginDTO = objectMapper.readValue(messageBody, LoginDTO.class);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = loginDTO.getUsername();
        String password = loginDTO.getPassword();

        // spring security 에서 username 과 password 를 검증하기 위해서는 token 에 담아야 함, dto 처럼 담아서 넘겨주기, 마지막은 role
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token 에 담은 검증을 위한 AuthenticationManager 로 전달
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행하는 method (여기서 jwt 를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Authentication authentication) {

//        // Authentication 객체에서 사용자 정보를 CustomUserDetails 타입으로 가져오기
//        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
//        // CustomUserDetails 객체에서 사용자 이름을 가져오기
//        String username = customUserDetails.getUsername();
//
//        // Authentication 객체에서 사용자 권한 목록을 가져오기
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        // 권한 목록에서 첫 번째 권한을 가져오기 위해 Iterator 사용
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//        // 사용자 권한 가져오기
//        String role = auth.getAuthority();
//
//        // JWT 토큰 생성 (username, role, 만료시간 10시간)
//        String token = jwtUtil.createJwt(username, role, 60 * 60 * 10L);
//
//        // 응답 헤더에 JWT 토큰을 추가 (Authorization 헤더에 Bearer 토큰으로 추가)
//        response.addHeader("Authorization", "Bearer " + token);

        // 유저 정보
        String username = authentication.getName();
        // Authentication 객체에서 사용자 권한 목록을 가져오기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        // 권한 목록에서 첫 번째 권한을 가져오기 위해 Iterator 사용
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        // 사용자 권한 가져오기
        String role = auth.getAuthority();

        // 토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // 응답 생성
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    // 로그인 실패 시 실행하는 method
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        // HTTP 상태 코드를 401(Unauthorized)로 설정하여 인증 실패를 알림
        response.setStatus(401);
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        // cookie.setSecure(true); https 통신에서 사용
        // cookie.setPath("/"); 쿠키가 적용될 범위
        // js로 접근하는 xss 공격을 방어
        cookie.setHttpOnly(true);

        return cookie;
    }
}
