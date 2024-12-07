package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.entity.RefreshEntity;
import com.example.springsecurityjwt.jwt.JWTUtil;
import com.example.springsecurityjwt.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class ReissueService {

    private final JWTUtil jwtUtil;

    private final RefreshRepository refreshRepository;

    public String reissue(HttpServletRequest request, HttpServletResponse response) {

        // get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {

            // response status code
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Refresh token is null");
        }

        // expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            // response status code
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Refresh token is expired");
        }

        // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {

            //response status code
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid refresh token");
        }

        // DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {

            // response body
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid refresh token");
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // make new JWT
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // Refresh 토큰 저장 DB에 기존의 RefreshToken 삭제 후 새 RefreshToken 저장
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, newRefresh, 86400000L);

        // response
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));

        return newAccess;
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

    // 저장소에 refreshToken 을 저장하는 method
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {
        // expireMs 는 만료 시간 -> Date 를 통해 날짜 만들기
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = RefreshEntity.buildRefreshEntity(username, refresh, date.toString());

        refreshRepository.save(refreshEntity);
    }
}
