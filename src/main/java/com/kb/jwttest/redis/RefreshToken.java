package com.kb.jwttest.redis;

import jakarta.persistence.Id;
import lombok.*;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@RedisHash(value = "refresh_token")
public class RefreshToken {
    @Id
    private String id;
    @Indexed
    private String token;
    @TimeToLive
    private long ttl;

    public RefreshToken(String token) {
        this.id = token;
        this.token = token;
    }
}