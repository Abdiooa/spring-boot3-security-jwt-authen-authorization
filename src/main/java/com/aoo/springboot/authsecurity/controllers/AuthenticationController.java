package com.aoo.springboot.authsecurity.controllers;

import com.aoo.springboot.authsecurity.dto.AuthRequest;
import com.aoo.springboot.authsecurity.dto.JwtResponseDto;
import com.aoo.springboot.authsecurity.dto.RegisterUserDto;
import com.aoo.springboot.authsecurity.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationService service;

        @PostMapping("/signup")
    public ResponseEntity<JwtResponseDto> signup(
            @RequestBody RegisterUserDto registerUserDto){
        return ResponseEntity.ok(service.signup(registerUserDto));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<JwtResponseDto> authenticate(
            @RequestBody AuthRequest authRequest){
        return ResponseEntity.ok(service.authenticate(authRequest));
    }
}
