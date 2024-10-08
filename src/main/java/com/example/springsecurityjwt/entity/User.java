package com.example.springsecurityjwt.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role;

    @Builder
    private User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public static User buildUser(String username, String password, String role) {
        return User.builder()
                .username(username)
                .password(password)
                .role(role)
                .build();
    }
}
