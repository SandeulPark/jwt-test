package com.kb.jwttest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kb.jwttest.dto.UserJoinCommand;
import com.kb.jwttest.entity.UserEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
class JwtTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired BCryptPasswordEncoder bCryptPasswordEncoder;

    @Test
    void join() throws Exception {
        // Given
        UserJoinCommand userJoinCommand = new UserJoinCommand("산드로", "1234");

        // When
        ResultActions resultActions = mvc.perform(post("/join")
                .content(objectMapper.writeValueAsString(userJoinCommand))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .characterEncoding(StandardCharsets.UTF_8)
        );

        // Then
        resultActions
                .andExpect(status().isOk())
                .andExpectAll(
                        jsonPath("$.username").value("산드로"),
                        jsonPath("$.password").exists(),
                        jsonPath("$.role").value("ROLE_ADMIN")
                );

        assertThat(userRepository.findAll()).hasSize(1);

        UserEntity userEntity = userRepository.findByUsername(userJoinCommand.username()).orElseThrow();
        assertThat(userEntity.getUsername()).isEqualTo("산드로");
        assertThat(userEntity.getPassword()).isNotNull();
        assertThat(userEntity.getRole()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    void join_duplicate() throws Exception {
        // Given
        userRepository.save(UserEntity.builder().username("산드로").password("1234").build());

        UserJoinCommand userJoinCommand = new UserJoinCommand("산드로", "1234");

        // When
        ResultActions resultActions = mvc.perform(post("/join")
                .content(objectMapper.writeValueAsString(userJoinCommand))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .characterEncoding(StandardCharsets.UTF_8)
        );

        // Then
        resultActions
                .andExpect(status().isBadRequest())
                .andExpectAll(
                        jsonPath("$.message").value("이미 존재하는 회원입니다.")
                );

        assertThat(userRepository.findAll()).hasSize(1);
    }

    @Test
    void login() throws Exception {
        // Given
        userRepository.save(UserEntity.builder().username("산드로").password(bCryptPasswordEncoder.encode("1234")).build());

        // When
        ResultActions resultActions = mvc.perform(post("/login")
                .param("username", "산드로")
                .param("password", "1234")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .characterEncoding(StandardCharsets.UTF_8)
        );

        // Then
        resultActions
                .andExpect(status().isOk());
    }
}
