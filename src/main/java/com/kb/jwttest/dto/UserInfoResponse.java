package com.kb.jwttest.dto;

import com.kb.jwttest.entity.UserEntity;

public record UserInfoResponse(
        String username,
        String password,
        String role
) {
    public static UserInfoResponse from(UserEntity user) {
        return new UserInfoResponse(
                user.getUsername(),
                user.getPassword(),
                user.getRole()
        );
    }
}
