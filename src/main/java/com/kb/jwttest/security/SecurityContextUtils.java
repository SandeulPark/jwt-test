package com.kb.jwttest.security;

import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityContextUtils {
    public static String getCurrentUsername() {
        return SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();
    }

    public static String getCurrentRole() {
        return SecurityContextHolder.getContext()
                .getAuthentication()
                .getAuthorities()
                .stream()
                .findAny()
                .orElseThrow()
                .getAuthority();
    }
}
