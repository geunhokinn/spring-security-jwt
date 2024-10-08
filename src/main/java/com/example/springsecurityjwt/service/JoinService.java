package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.dto.JoinDTO;
import com.example.springsecurityjwt.entity.User;
import com.example.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public void joinProcess(JoinDTO joinDTO) {

        Boolean isUser = userRepository.existsByUsername(joinDTO.getUsername());
        if (Boolean.TRUE.equals(isUser)) {
            throw new RuntimeException("동일한 아이디가 이미 존재합니다.");
        }

        User user = User.buildUser(
                joinDTO.getUsername(),
                bCryptPasswordEncoder.encode(joinDTO.getPassword()),
                "ROLE_ADMIN"
        );

        userRepository.save(user);
    }
}
