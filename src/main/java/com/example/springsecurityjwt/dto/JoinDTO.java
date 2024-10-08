package com.example.springsecurityjwt.dto;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class JoinDTO {

    private String username;
    private String password;

    @Builder
    public JoinDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
