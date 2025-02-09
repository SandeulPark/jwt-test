package com.kb.jwttest.dto;

public record Tokens(
        String accessToken,
        String refreshToken
) {
}
