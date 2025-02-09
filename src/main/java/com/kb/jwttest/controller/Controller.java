package com.kb.jwttest.controller;

import com.kb.jwttest.dto.Tokens;
import com.kb.jwttest.dto.UserInfoResponse;
import com.kb.jwttest.dto.UserJoinCommand;
import com.kb.jwttest.jwt.HttpResponseUtil;
import com.kb.jwttest.jwt.JwtService;
import com.kb.jwttest.security.SecurityContextUtils;
import com.kb.jwttest.service.JoinService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class Controller {
    private final JoinService joinService;
    private final JwtService jwtService;

    @GetMapping("/")
    public Map<String, Object> main() {
        return Map.of(
                "currentUsername", SecurityContextUtils.getCurrentUsername(),
                "currentRole", SecurityContextUtils.getCurrentRole()
        );
    }

    @PostMapping("/join")
    public UserInfoResponse join(@RequestBody UserJoinCommand command) {
        return joinService.join(command);
    }

    @GetMapping("/admin")
    public String adminP() {
        return "admin Controller";
    }

    @PostMapping("/login")
    public String login() {
        // 로그인 처리
        return "로그인 성공";
    }

    @PostMapping("/reissue")
    public ResponseEntity reissue(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals("refresh"))
                .findAny()
                .orElseThrow()
                .getValue();

        try {
            Tokens tokens = jwtService.reissue(refreshToken);
            HttpResponseUtil.setSuccessResponse(response, tokens.accessToken(), tokens.refreshToken());
            return ResponseEntity.ok().build();

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
