package com.aoo.springboot.authsecurity.controllers;

import com.aoo.springboot.authsecurity.dto.AuthRequest;
import com.aoo.springboot.authsecurity.dto.JwtResponseDto;
import com.aoo.springboot.authsecurity.dto.MessageResponse;
import com.aoo.springboot.authsecurity.dto.RegisterUserDto;
import com.aoo.springboot.authsecurity.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")

//@CrossOrigin(origins = "http://localhost:8050",
//                maxAge = 3600, allowCredentials = "true")
public class AuthenticationController {
    private final AuthenticationService service;

        @PostMapping("/signup")
    public ResponseEntity<MessageResponse> signup(
            @RequestBody RegisterUserDto registerUserDto){
        return ResponseEntity.ok(service.signup(registerUserDto));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(
            @RequestBody AuthRequest authRequest){
        JwtResponseDto cookie = service.authenticate(authRequest);

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.getResponseCookie().toString())
                .body(cookie.getUserResponse());
    }
}
