package com.kb.jwttest.jwt;

import com.kb.jwttest.redis.RefreshToken;
import com.kb.jwttest.redis.RefreshTokenRepository;
import com.kb.jwttest.security.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 요청에 있는 로그인 정보를 꺼내서 인증을 하고, JWT를 발급하는 필터
 */
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtUtils jwtUtils;
    private final RefreshTokenRepository refreshTokenRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JwtUtils jwtUtils, RefreshTokenRepository refreshTokenRepository) {
        super(authenticationManager);
        this.jwtUtils = jwtUtils;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return super.getAuthenticationManager().authenticate(authToken); // 검증을 위임
    }

    // 인증 성공 시
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();
        GrantedAuthority grantedAuthority = userDetails.getAuthorities().stream().findAny().orElseThrow();

        String access = jwtUtils.createAccessToken(userDetails.getUsername(), grantedAuthority.getAuthority());
        String refresh = jwtUtils.createRefreshToken(userDetails.getUsername(), grantedAuthority.getAuthority());

        refreshTokenRepository.save(new RefreshToken(refresh));

        HttpResponseUtil.setSuccessResponse(response, access, refresh);
    }

    // 인증 실패 시
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}
