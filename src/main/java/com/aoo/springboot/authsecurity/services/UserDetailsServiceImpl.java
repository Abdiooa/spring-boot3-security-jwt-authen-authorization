package com.aoo.springboot.authsecurity.services;

import com.aoo.springboot.authsecurity.models.CustomUserDetails;
import com.aoo.springboot.authsecurity.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserService {
    private final UserRepository userRepository;


    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                var user = userRepository.findByEmail(username)
                        .orElseThrow(()-> new UsernameNotFoundException("User not found"));

                return new CustomUserDetails(user);
            }
        };
    }
}
