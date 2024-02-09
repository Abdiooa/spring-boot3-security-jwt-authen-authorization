package com.aoo.springboot.authsecurity.dto;

import com.aoo.springboot.authsecurity.models.EnumRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserDto {

    private String username;
    private String email;
    private String password;
}
