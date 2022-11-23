package com.ansv.authorizationserver.constants;

import org.springframework.stereotype.Component;

@Component
public interface MessageConstans {
    String INVALID_TOKEN = "Invalid Token";
    String VALID_TOKEN = "Valid token for user ";
    String USERNAME_OR_PASSWORD_EMPTY = "Username or Password should not be empty";
    String USERNAME_OR_PASSWORD_INVALID = "Bad credentials";
    String USERNAME_INACTIVE = "User is inactive";
    String SYSTEM_ERROR = "System error";
}
