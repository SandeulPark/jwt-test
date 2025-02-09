package com.kb.jwttest.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

public class HttpResponseUtil {
    public static void setSuccessResponse(HttpServletResponse response, String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("access", accessToken);
        response.addCookie(createCookie("refresh", refreshToken));
    }

    private static Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 24);
        cookie.setHttpOnly(true);
        return cookie;
    }
}
