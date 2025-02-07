package com.kb.jwttest.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/login")
    public String login() {
        // 로그인 처리
        return "로그인 성공";
    }
}
