package com.kb.jwttest.service;

import com.kb.jwttest.UserRepository;
import com.kb.jwttest.dto.UserInfoResponse;
import com.kb.jwttest.dto.UserJoinCommand;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserInfoResponse join(UserJoinCommand command) {
        String username = command.username();

        if (userRepository.existsByUsername(username))
            throw new IllegalArgumentException("이미 존재하는 회원입니다.");

        return UserInfoResponse.from(userRepository.save(command.toEntity(bCryptPasswordEncoder)));
    }
}
