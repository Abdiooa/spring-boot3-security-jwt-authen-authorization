package com.aoo.springboot.authsecurity.dto;

import com.aoo.springboot.authsecurity.models.EnumRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private String username;
    private String email;
    private String password;
    private EnumRole role;
    private Date createdAt;
    private Date updatedAt;
}
