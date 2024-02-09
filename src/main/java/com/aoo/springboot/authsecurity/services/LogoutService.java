package com.aoo.springboot.authsecurity.services;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private final JwtService jwtService;
    private final UserService userService;
    private final HandlerExceptionResolver handlerExceptionResolver;
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        try {
            String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);
            if (jwtService.isTokenInvalidated(jwt)) {
                response.setStatus(HttpStatus.UNAUTHORIZED.value()); // Token is already invalidated
                response.getWriter().write("Login First please!");
                response.getWriter().flush();
                response.getWriter().close();
                return;
            }
            if(userEmail != null){
                UserDetails userDetails = userService.userDetailsService()
                        .loadUserByUsername(userEmail);
                if(jwtService.isTokenValid(jwt, userDetails)){
                    jwtService.invalidateToken(jwt);
                    SecurityContextHolder.clearContext();
                }
            }
        }catch (Exception exception){
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }
    }
}
