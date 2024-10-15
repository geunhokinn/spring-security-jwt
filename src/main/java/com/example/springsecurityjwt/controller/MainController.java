package com.example.springsecurityjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;

@RestController
public class MainController {

    @GetMapping("/")
    public String mainP(){

        // 세션 현재 사용자의 아이디
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        // 세션 현재 사용자 role
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // Authentication 객체에서 사용자 권한 목록을 가져오기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        // 권한 목록에서 첫 번째 권한을 가져오기 위해 Iterator 사용
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        // 사용자 권한 가져오기
        String role = auth.getAuthority();

        return "Main Controller" + username + role;
    }
}
