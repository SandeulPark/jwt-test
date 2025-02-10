package com.kb.jwttest.jwt;

import com.kb.jwttest.dto.Tokens;
import com.kb.jwttest.redis.RefreshToken;
import com.kb.jwttest.redis.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class JwtService {
    private final JwtUtils jwtUtils;
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public Tokens reissue(String refreshToken) {
        validateRefreshToken(refreshToken);

        String newAccessToken = jwtUtils.createAccessToken(jwtUtils.getUsername(refreshToken), jwtUtils.getRole(refreshToken));
        String newRefreshToken = jwtUtils.createRefreshToken(jwtUtils.getUsername(refreshToken), jwtUtils.getRole(refreshToken));

        refreshTokenRepository.deleteByToken(refreshToken);
        refreshTokenRepository.save(new RefreshToken(newRefreshToken));

        return new Tokens(newAccessToken, newRefreshToken);
    }

    public void validateRefreshToken(String refreshToken) {
        if (jwtUtils.isExpired(refreshToken))
            throw new RuntimeException("refresh token is expired");

        if (!jwtUtils.isRefreshToken(refreshToken))
            throw new RuntimeException("token is invalid");

        if (!refreshTokenRepository.existsByToken(refreshToken))
            throw new RuntimeException("refresh token is not found");
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(refreshTokenRepository::delete);
    }
}
