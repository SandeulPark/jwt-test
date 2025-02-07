package com.kb.jwttest.dto;

public record UserLoginCommand(
        String username,
        String password
) {
}
