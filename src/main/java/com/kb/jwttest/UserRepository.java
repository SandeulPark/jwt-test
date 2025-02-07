package com.kb.jwttest;

import com.kb.jwttest.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    boolean existsByUsername(String userName);

    Optional<UserEntity> findByUsername(String username);
}
