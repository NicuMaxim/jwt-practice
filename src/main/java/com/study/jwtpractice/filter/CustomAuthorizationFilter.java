package com.study.jwtpractice.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.study.jwtpractice.utility.Utility;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getServletPath().equals("/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response);
        } else {

            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    DecodedJWT decodedJWT = Utility.decodeJwtToken(token);
                    String username = decodedJWT.getSubject();
                    String [] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities = Utility.rolesToGrantedAuthorities(roles);

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    log.info("User {} identified by access token {} has roles: {}", username, token, roles);
                    filterChain.doFilter(request, response);

                } catch (Exception exception) {
                    Utility.badTokenExceptionHandling(exception, response);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
