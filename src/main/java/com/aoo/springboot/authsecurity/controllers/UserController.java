package com.aoo.springboot.authsecurity.controllers;

import com.aoo.springboot.authsecurity.dto.UserResponse;
import com.aoo.springboot.authsecurity.models.User;
import com.aoo.springboot.authsecurity.repositories.UserRepository;
import com.aoo.springboot.authsecurity.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
//@CrossOrigin(origins = "http://localhost:8050",
//        maxAge = 3600, allowCredentials = "true")
public class UserController {
    private final UserService userService;
    private final UserRepository userRepository;
    @GetMapping("/me")
    public ResponseEntity<UserResponse> authenticatedUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        return ResponseEntity.ok(userService.mapToUserResponse(userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(()-> new UsernameNotFoundException("User not found"))));
    }

    @GetMapping("/")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<UserResponse>> allUsers(){
        List<UserResponse> users = new ArrayList<>();
        userRepository.findAll().forEach(user -> users.add(userService.mapToUserResponse(user)));
        return ResponseEntity.ok(users);
    }
}
