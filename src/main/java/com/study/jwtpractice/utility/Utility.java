package com.study.jwtpractice.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.*;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class Utility {

    public static DecodedJWT decodeJwtToken(String token) {
        JWTVerifier verifier = JWT.require(getAlgorithm()).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT;
    }

    public static Algorithm getAlgorithm() {
        return Algorithm.HMAC256("secret".getBytes());
    }

    public static void addTokensToResponse(String access_token, String refresh_token, HttpServletResponse response) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    public static Collection<SimpleGrantedAuthority> rolesToGrantedAuthorities(String [] roles) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role));
        });
        return authorities;
    }

    public static void badTokenExceptionHandling(Exception exception, HttpServletResponse response) throws IOException {
        log.error("Error logging in: {}", exception.getMessage());
        response.setHeader("error", exception.getMessage());
        response.setStatus(FORBIDDEN.value());

        Map<String, String> error = new HashMap<>();
        error.put("error_message", exception.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
