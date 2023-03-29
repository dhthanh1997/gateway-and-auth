package com.ansv.gateway.handler;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import javax.naming.AuthenticationException;

public class JwtTokenNotValidException extends JwtException {


    public JwtTokenNotValidException(String message) {
        super(message);
    }

    public JwtTokenNotValidException(String message, Throwable cause) {
        super(message, cause);
    }
}
