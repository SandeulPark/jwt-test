package com.kb.jwttest.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    private final static String ACCESS = "access";
    private final static String REFRESH = "refresh";
    private final static String USERNAME = "username";
    private final static String ROLE = "role";
    private final static String CATEGORY = "category";

    private final SecretKeySpec secretKey;
    private final long accesExpiredMs;
    private final long refreshExpiredMs;

    public JwtUtils(@Value("${jwt.secret}") String secret,
                    @Value("${jwt.accesExpiredMs}") long accesExpiredMs,
                    @Value("${jwt.refreshExpiredMs}") long refreshExpiredMs) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        this.accesExpiredMs = accesExpiredMs;
        this.refreshExpiredMs = refreshExpiredMs;
    }

    public String getUsername(String token) {
        return getPayload(token).get(USERNAME, String.class);
    }

    public String getRole(String token) {
        return getPayload(token).get(ROLE, String.class);
    }

    public String getCategory(String token) {
        return getPayload(token).get(CATEGORY, String.class);
    }

    public boolean isExpired(String token) {
        try {
            return getPayload(token)
                    .getExpiration()
                    .before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    public boolean isAccessToken(String token) {
        return getCategory(token).equals(ACCESS);
    }

    public boolean isRefreshToken(String refreshToken) {
        return getCategory(refreshToken).equals(REFRESH);
    }

    private Claims getPayload(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String createAccessToken(String username, String role) {
        return createToken(ACCESS, username, role, accesExpiredMs);
    }

    public String createRefreshToken(String username, String role) {
        return createToken(REFRESH, username, role, refreshExpiredMs);
    }

    public String createToken(String category, String username, String role, long expiredMs) {
        return Jwts.builder()
                .claim(CATEGORY, category)
                .claim(USERNAME, username)
                .claim(ROLE, role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}
