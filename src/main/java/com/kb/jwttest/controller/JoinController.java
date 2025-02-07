package com.kb.jwttest.controller;

import com.kb.jwttest.dto.UserInfoResponse;
import com.kb.jwttest.dto.UserJoinCommand;
import com.kb.jwttest.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class JoinController {
    private final JoinService joinService;

    @PostMapping("/join")
    public UserInfoResponse join(@RequestBody UserJoinCommand command) {
        return joinService.join(command);
    }
}
