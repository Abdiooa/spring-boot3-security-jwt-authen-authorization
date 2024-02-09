package com.aoo.springboot.authsecurity.services;

import com.aoo.springboot.authsecurity.dto.AuthRequest;
import com.aoo.springboot.authsecurity.dto.JwtResponseDto;
import com.aoo.springboot.authsecurity.dto.RegisterUserDto;

public interface AuthenticationService {
    JwtResponseDto signup(RegisterUserDto registerUserDto);
    JwtResponseDto authenticate(AuthRequest authRequest);
}
