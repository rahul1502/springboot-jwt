package com.example.jwt.auth;

import org.springframework.security.core.userdetails.User;
import java.util.Optional;

public interface ApplicationUserDao {
    public Optional<User> selectApplicationUserByUsername(String username);
}
