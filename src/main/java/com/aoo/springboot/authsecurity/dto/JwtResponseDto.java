package com.aoo.springboot.authsecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.ResponseCookie;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponseDto {
    private ResponseCookie responseCookie;
    private UserResponse userResponse;
}
