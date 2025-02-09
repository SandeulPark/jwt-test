package com.kb.jwttest.redis;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
    Optional<RefreshToken> findByToken(String token);

    boolean existsByToken(String token);

    void deleteByToken(String refreshToken);
}