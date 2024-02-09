package com.aoo.springboot.authsecurity.services;

import com.aoo.springboot.authsecurity.dto.UserResponse;
import com.aoo.springboot.authsecurity.models.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    UserDetailsService userDetailsService();
    UserResponse mapToUserResponse(User user);
}
