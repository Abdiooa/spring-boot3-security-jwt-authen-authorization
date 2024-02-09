package com.aoo.springboot.authsecurity.services;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
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
        final String jwtTokenCookie = parseJwtToken(request);
        if (jwtTokenCookie == null) {
            return;
        }

        try {
            final String userEmail = jwtService.extractUsername(jwtTokenCookie);
            if (jwtService.isTokenInvalidated(jwtTokenCookie)) {
                response.setStatus(HttpStatus.UNAUTHORIZED.value()); // Token is already invalidated
                response.getWriter().write("Login First please!");
                response.getWriter().flush();
                response.getWriter().close();
                return;
            }
            if(userEmail != null){
                UserDetails userDetails = userService.userDetailsService()
                        .loadUserByUsername(userEmail);
                if(jwtService.isTokenValid(jwtTokenCookie, userDetails)){
                    jwtService.invalidateToken(jwtTokenCookie);
                    SecurityContextHolder.clearContext();
                    ResponseCookie cookie = jwtService.getCleanJwtCookie();
                    Cookie servletCookie = new Cookie(cookie.getName(), cookie.getValue());
                    servletCookie.setPath(cookie.getPath());
                    response.addCookie(servletCookie);
                }
            }
        }catch (Exception exception){
            handlerExceptionResolver.resolveException(request, response, null, exception);
        }
    }
    private String parseJwtToken(HttpServletRequest request){
        return jwtService.getJwtFromCookies(request);
    }
}
