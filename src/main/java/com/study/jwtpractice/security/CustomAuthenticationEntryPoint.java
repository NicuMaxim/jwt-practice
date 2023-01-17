package com.study.jwtpractice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

          response.setContentType(APPLICATION_JSON_VALUE);
          String errorMessage;

          if (response.getStatus() == UNAUTHORIZED.value()) {
              errorMessage = "Invalid login or password";
          } else if (response.getStatus() == FORBIDDEN.value()) {
              //log.error();
              errorMessage = "You have no access to this resource";
          } else {
              errorMessage = "Authentication failed";
          }
          new ObjectMapper().writeValue(response.getOutputStream(), errorMessage);
    }
}
