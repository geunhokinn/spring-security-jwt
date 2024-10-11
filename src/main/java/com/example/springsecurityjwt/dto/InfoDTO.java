package com.example.springsecurityjwt.dto;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class InfoDTO {

    private String username;
    private String password;
    private String role;

    @Builder
    public InfoDTO(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }
}
