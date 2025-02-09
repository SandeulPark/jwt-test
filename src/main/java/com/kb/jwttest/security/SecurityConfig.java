package com.kb.jwttest.security;

import com.kb.jwttest.jwt.JwtFilter;
import com.kb.jwttest.jwt.JwtUtils;
import com.kb.jwttest.jwt.LoginFilter;
import com.kb.jwttest.redis.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtils jwtUtils;
    private final RefreshTokenRepository refreshTokenRepository;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public UsernamePasswordAuthenticationFilter loginFilter() throws Exception {
        return new LoginFilter(authenticationManager(), jwtUtils, refreshTokenRepository);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(cors ->
                        cors.configurationSource(request -> {
                            CorsConfiguration conf = new CorsConfiguration();
                            conf.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                            conf.setAllowedMethods(Collections.singletonList("*"));
                            conf.setAllowCredentials(true);
                            conf.setAllowedHeaders(Collections.singletonList("*"));
                            conf.setMaxAge(3600L);
                            conf.setExposedHeaders(Collections.singletonList("Authorization"));
                            return conf;
                        }))

                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/", "/join", "/reissue").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated())

                // JWT 방식은 세션을 STATELESS로 설정해야 한다.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilterBefore(new JwtFilter(jwtUtils), LoginFilter.class)
                .addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
