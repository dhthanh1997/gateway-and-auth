package com.ansv.gateway.handler;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ResponseStatusException;

public class ErrorWebException extends ResponseStatusException {


    public ErrorWebException(HttpStatus status) {
        super(status);
    }

    public ErrorWebException(HttpStatus status, String reason) {
        super(status, reason);
    }

    public ErrorWebException(HttpStatus status, String reason, Throwable cause) {
        super(status, reason, cause);
    }

    public ErrorWebException(int rawStatusCode, String reason, Throwable cause) {
        super(rawStatusCode, reason, cause);
    }
}
