package com.kb.jwttest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kb.jwttest.dto.UserJoinCommand;
import com.kb.jwttest.entity.UserEntity;
import com.kb.jwttest.jwt.JwtUtils;
import com.kb.jwttest.redis.RefreshToken;
import com.kb.jwttest.redis.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest
class JwtTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired JwtUtils jwtUtils;
    @Autowired RefreshTokenRepository refreshTokenRepository;

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @DisplayName("회원가입")
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

    @DisplayName("로그인 성공 시 accessToken,refreshToken이 발급되어야 한다.")
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
        MvcResult mvcResult = resultActions
                .andExpect(status().isOk())
                .andExpect(result -> {
                    MockHttpServletResponse response = result.getResponse();

                    String accessToken = response.getHeader("access");
                    assertThat(jwtUtils.getUsername(accessToken)).isEqualTo("산드로");
                    assertThat(jwtUtils.getRole(accessToken)).isEqualTo("ROLE_ADMIN");
                    assertThat(jwtUtils.getCategory(accessToken)).isEqualTo("access");

                    Cookie refreshTokenCookie = response.getCookie("refresh");
                    String refreshToken = Objects.requireNonNull(refreshTokenCookie).getValue();
                    assertThat(jwtUtils.getUsername(refreshToken)).isEqualTo("산드로");
                    assertThat(jwtUtils.getRole(refreshToken)).isEqualTo("ROLE_ADMIN");
                    assertThat(jwtUtils.getCategory(refreshToken)).isEqualTo("refresh");
                })
                .andDo(print())
                .andReturn();

        String refresh = mvcResult.getResponse().getCookie("refresh").getValue();

        RefreshToken foundRefreshToken = refreshTokenRepository.findByToken(refresh).orElseThrow();
        assertThat(foundRefreshToken).isNotNull();
    }

    @DisplayName("인증이 필요한 자원 요청 시 토큰이 유효하지 않은 경우 자원 접근이 거부된다.")
    @Test
    void AccessDenied() throws Exception {
        mvc.perform(get("/hi"))
                .andExpect(status().isForbidden())
                .andDo(print());
    }

    @DisplayName("자원 접근 시 accessToken이 유효하다면 접근이 가능해야 한다.")
    @Test
    void auth() throws Exception {
        // Given
        String accessToken = getAccessToken();

        // When
        ResultActions resultActions = mvc.perform(get("/admin")
                .header("access", accessToken)
        );

        // Then
        resultActions
                .andExpect(status().isOk())
                .andDo(print());
    }

    @DisplayName("현재 사용자의 정보를 반환한다.")
    @Test
    void main() throws Exception {
        // Given
        String accessToken = getAccessToken();

        // When
        ResultActions resultActions = mvc.perform(get("/")
                .header("access", accessToken)
        );

        // Then
        resultActions
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentUsername").value("산드로"))
                .andExpect(jsonPath("$.currentRole").value("ROLE_ADMIN"))
                .andDo(print());
    }

    @DisplayName("토큰이 만료된 경우 토큰 만료 응답이 내려온다.")
    @Test
    void expirationTest() throws Exception {
        // Given
        String accessToken = jwtUtils.createToken("access", "산드로", "ROLE_ADMIN", 1L);

        // When
        ResultActions resultActions = mvc.perform(get("/")
                .header("access", accessToken)
        );

        // Then
        resultActions
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("access token expired"))
                .andDo(print());
    }

    @DisplayName("accessToken을 재발급한다.")
    @Test
    void reissue() throws Exception {
        // Given
        String refreshToken = getRefreshToken();

        // When
        ResultActions resultActions = mvc.perform(post("/reissue")
                .cookie(new Cookie("refresh", refreshToken))
        );

        // Then
        resultActions
                .andExpect(status().isOk())
                .andExpect(result -> {
                    MockHttpServletResponse response = result.getResponse();

                    String accessToken = response.getHeader("access");
                    assertThat(jwtUtils.getUsername(accessToken)).isEqualTo("산드로");
                    assertThat(jwtUtils.getRole(accessToken)).isEqualTo("ROLE_ADMIN");
                    assertThat(jwtUtils.getCategory(accessToken)).isEqualTo("access");

                    Cookie refreshTokenCookie = response.getCookie("refresh");
                    String newRefreshToken = Objects.requireNonNull(refreshTokenCookie).getValue();
                    assertThat(jwtUtils.getUsername(newRefreshToken)).isEqualTo("산드로");
                    assertThat(jwtUtils.getRole(newRefreshToken)).isEqualTo("ROLE_ADMIN");
                    assertThat(jwtUtils.getCategory(newRefreshToken)).isEqualTo("refresh");
                })
                .andDo(print());
    }

    @DisplayName("로그아웃 시 refreshToken이 제거된다.")
    @Test
    void logout() throws Exception {
        // Given
        String refreshToken = getRefreshToken();

        // When
        ResultActions resultActions = mvc.perform(post("/logout")
                .cookie(new Cookie("refresh", refreshToken))
        );

        // Then
        MvcResult mvcResult = resultActions
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();

        MockHttpServletResponse response = mvcResult.getResponse();
        assertThat(response.getHeader("access")).isNull();
        assertThat(response.getCookie("refresh").getValue()).isNull();

        assertThat(refreshTokenRepository.existsByToken(refreshToken)).isFalse();
    }

    private String getAccessToken() throws Exception {
        return getTokenResponse().getHeader("access");
    }

    private String getRefreshToken() throws Exception {
        return getTokenResponse().getCookie("refresh").getValue();
    }

    private MockHttpServletResponse getTokenResponse() throws Exception {
        userRepository.save(UserEntity.builder().username("산드로").password(bCryptPasswordEncoder.encode("1234")).build());

        return mvc.perform(post("/login")
                        .param("username", "산드로")
                        .param("password", "1234")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .characterEncoding(StandardCharsets.UTF_8)
                ).andDo(print())
                .andReturn()
                .getResponse();
    }
}
