package com.aoo.springboot.authsecurity.services;

import com.aoo.springboot.authsecurity.dto.AuthRequest;
import com.aoo.springboot.authsecurity.dto.JwtResponseDto;
import com.aoo.springboot.authsecurity.dto.MessageResponse;
import com.aoo.springboot.authsecurity.dto.RegisterUserDto;
import com.aoo.springboot.authsecurity.models.*;
import com.aoo.springboot.authsecurity.repositories.TokenRepository;
import com.aoo.springboot.authsecurity.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService{
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;
    private final UserService userService;
    @Override
    public MessageResponse signup(RegisterUserDto registerUserDto) {


        var user = User.builder()
                .username(registerUserDto.getUsername())
                .email(registerUserDto.getEmail())
                .password(passwordEncoder.encode(registerUserDto.getPassword()))
                .role(EnumRole.USER)
                .build();
        userRepository.save(user);
        return MessageResponse.builder()
                .message("User Registered Successfully!")
                .build();
    }

    @Override
    public JwtResponseDto authenticate(AuthRequest authRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authRequest.getEmail(),
                authRequest.getPassword()
        ));

        var user = userRepository.findByEmail(authRequest.getEmail())
                .orElseThrow();
        var jwtTokenCookie = jwtService.generateJwtCookie((user.getEmail()));
        revokeAllUserTokens(user);
        saveUserToken(user, jwtTokenCookie.getValue());
        return JwtResponseDto.builder()
                .responseCookie(jwtTokenCookie)
                .userResponse(userService.mapToUserResponse(user))
                .build();
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(User user, String jwtToken){
        var token = Token.builder()
                .token(jwtToken)
                .user(user)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

}
