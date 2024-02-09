package com.aoo.springboot.authsecurity.config;

import com.aoo.springboot.authsecurity.services.JwtService;
import com.aoo.springboot.authsecurity.services.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserService userService;
    private final HandlerExceptionResolver handlerExceptionResolver;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        final String jwtToken = parseJwt(request);
        if (jwtToken == "") {
            filterChain.doFilter(request, response);
            return;
        }else {
            try {
                if (jwtService.isTokenInvalidated(jwtToken)) {
                    ResponseCookie cookie = jwtService.getCleanJwtCookie();
                    Cookie servletCookie = new Cookie(cookie.getName(), cookie.getValue());
                    servletCookie.setPath(cookie.getPath());
                    response.addCookie(servletCookie);
                    response.setStatus(HttpStatus.FORBIDDEN.value()); // Token is already invalidated
                    response.getWriter().write("Login please!");
                    response.getWriter().flush();
                    response.getWriter().close();
                    return;
                }
                final String userEmail = jwtService.extractUsername(jwtToken);
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (userEmail != null && authentication == null) {
                    UserDetails userDetails = userService.userDetailsService()
                            .loadUserByUsername(userEmail);

                    if (jwtService.isTokenValid(jwtToken, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
                filterChain.doFilter(request, response);
            } catch (Exception exception) {

                handlerExceptionResolver.resolveException(request, response, null, exception);
            }
        }
    }
    private String parseJwt(HttpServletRequest request){
        return jwtService.getJwtFromCookies(request);
    }

}
