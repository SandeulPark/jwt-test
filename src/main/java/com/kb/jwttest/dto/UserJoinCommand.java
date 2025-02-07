package com.kb.jwttest.dto;

import com.kb.jwttest.entity.UserEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public record UserJoinCommand(
        String username,
        String password
) {
    public UserEntity toEntity(BCryptPasswordEncoder bCryptPasswordEncoder) {
        return UserEntity.builder()
                .username(username)
                .password(bCryptPasswordEncoder.encode(password))
                .role("ROLE_ADMIN")
                .build();
    }
}
