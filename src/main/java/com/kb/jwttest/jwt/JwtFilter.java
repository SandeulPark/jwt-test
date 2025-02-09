package com.kb.jwttest.jwt;

import com.kb.jwttest.entity.UserEntity;
import com.kb.jwttest.security.CustomUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * 요청을 확인해서 JWT가 있으면 SecurityContextHolder에 저장한다.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = request.getHeader("access");

        if (accessToken == null) {
            log.debug("token null");
            filterChain.doFilter(request, response);
            return;
        }

        if (isExpired(response, accessToken)) return;

        if (isInvalidAccessToken(response, accessToken)) return;

        UsernamePasswordAuthenticationToken authenticationToken = getUsernamePasswordAuthenticationToken(accessToken);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request, response);
    }

    private boolean isExpired(HttpServletResponse response, String accessToken) throws IOException {
        try {
            jwtUtils.isExpired(accessToken);
        } catch (ExpiredJwtException e) {
            log.debug("token is expired");
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return true;
        }
        return false;
    }

    private boolean isInvalidAccessToken(HttpServletResponse response, String accessToken) throws IOException {
        String category = jwtUtils.getCategory(accessToken);

        if (!category.equals("access")) {
            log.debug("invalid access token");
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return true;
        }
        return false;
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String token) {
        UserEntity userEntity = UserEntity.builder().username(jwtUtils.getUsername(token)).role(jwtUtils.getRole(token)).build();
        CustomUserDetails userDetails = new CustomUserDetails(userEntity);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}
