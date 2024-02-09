package com.aoo.springboot.authsecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponseDto {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
}
