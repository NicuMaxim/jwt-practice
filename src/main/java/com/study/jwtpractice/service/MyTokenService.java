package com.study.jwtpractice.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.study.jwtpractice.model.Role;
import com.study.jwtpractice.model.User;
import com.study.jwtpractice.utility.Utility;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class MyTokenService {
    private final UserServiceImpl userService;

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                DecodedJWT decodedJWT = Utility.decodeJwtToken(refresh_token);
                String username = decodedJWT.getSubject();

                User user = userService.getUser(username);
                log.info("User {} requests new access token using refresh token {}", username, refresh_token);

                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(Utility.getAlgorithm());

                log.info("New access_token was created for user {}: {}", user.getUsername(), access_token);
                Utility.addTokensToResponse(access_token, refresh_token, response);

            } catch (Exception exception) {
                Utility.badTokenExceptionHandling(exception, response);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
}
