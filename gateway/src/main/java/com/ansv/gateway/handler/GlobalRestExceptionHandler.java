package com.ansv.gateway.handler;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.HibernateException;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.util.MultiValueMap;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import reactor.core.publisher.Mono;

import javax.persistence.EntityNotFoundException;
import javax.validation.ConstraintViolationException;
import java.sql.SQLException;


@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class GlobalRestExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * building response object to client
     *
     * @param apiError
     * @return
     */
    protected ResponseEntity<Object> buildResponseEntity(ApiError apiError) {
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }

//    protected Mono<ServerResponse> buildResponseEntityGateway(ApiError apiError) {
//        return new Mono<ServerResponse>(apiError, apiError.getStatus());
//    }

    /**
     * @param ex
     * @param headers
     * @param status
     * @param request
     * @return
     */
    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        String error = ex.getParameterName() + "parameter is missing";
        return buildResponseEntity(new ApiError(HttpStatus.BAD_REQUEST, error, ex));
    }

    /**
     * handling for validating error
     *
     * @param ex
     * @param headers
     * @param status
     * @param request
     * @return
     */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Validation error");
        apiError.addValidationErrors(ex.getBindingResult().getFieldErrors());
        apiError.addValidationError(ex.getBindingResult().getGlobalError());
        return buildResponseEntity(apiError);
    }

    /**
     * @param ex
     * @param headers
     * @param status
     * @param request
     * @return
     */
    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        StringBuilder builder = new StringBuilder();
        builder.append(ex.getContentType());
        builder.append("Media type is not supported. Supported media types are");
        ex.getSupportedMediaTypes().forEach(x -> builder.append(x).append(", "));
        ApiError apiError = new ApiError(HttpStatus.UNSUPPORTED_MEDIA_TYPE, builder.substring(0, builder.length() - 2), ex);
        return buildResponseEntity(apiError);
    }


    /**
     * @param ex
     * @param headers
     * @param status
     * @param request
     * @return
     */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        ServletWebRequest servletWebRequest = (ServletWebRequest) request;
        log.info("{} to {}", servletWebRequest.getHttpMethod(), servletWebRequest.getRequest().getServletPath());
        String error = "Malformed JSON request";
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, error, ex);
        return buildResponseEntity(apiError);
    }

    /**
     * @param ex
     * @param headers
     * @param status
     * @param request
     * @return
     */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotWritable(HttpMessageNotWritableException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        String error = "Error writing JSON output";
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, error, ex);
        return buildResponseEntity(apiError);
    }

    /**
     * @param ex
     * @param headers
     * @param status
     * @param request
     * @return
     */
    @Override
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
//        ServletWebRequest servletWebRequest = (ServletWebRequest) request;
        String error = String.format("Could not find the %s method URL %s", ex.getHttpMethod(), ex.getRequestURL());
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage(error);
        apiError.setDebugMessage(ex.getMessage());
        return buildResponseEntity(apiError);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers, HttpStatus status, WebRequest request) {
//        ServletWebRequest servletWebRequest = (ServletWebRequest) request;
        String error = String.format("Internal Server error");
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR);
        apiError.setMessage(error);
        apiError.setDebugMessage(ex.getMessage());
        return buildResponseEntity(apiError);
    }

    /**
     * entity not found
     *
     * @param ex
     * @return
     */
    @ExceptionHandler(EntityNotFoundException.class)
    protected ResponseEntity<Object> handleEntityNotFound(EntityNotFoundException ex) {
        ApiError apiError = new ApiError(HttpStatus.NOT_FOUND, ex);
        return buildResponseEntity(apiError);
    }

    /**
     * data integrity violation
     *
     * @param ex
     * @return
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    protected ResponseEntity<Object> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        if (ex.getCause() instanceof ConstraintViolationException) {
            return buildResponseEntity(new ApiError(HttpStatus.CONFLICT, ex));
        }
        return buildResponseEntity(new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, ex));
    }

    /**
     * @param ex
     * @param request
     * @return
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    protected ResponseEntity<Object> handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        String error = String.format("The parameter '$s' of value '%s' could not be converted to type '%s'"
                , ex.getName(), ex.getValue(), ex.getRequiredType().getSimpleName());
        apiError.setMessage(error);
        apiError.setDebugMessage(ex.getMessage());
        return buildResponseEntity(apiError);
    }


    /**
     * handling constraint violation - validation. Thrown when @Validated fails.
     *
     * @param ex
     * @return
     */
    @ExceptionHandler(ConstraintViolationException.class)
    protected ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException ex) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Validation error");
        apiError.addValidationErrors(ex.getConstraintViolations());
        return buildResponseEntity(apiError);
    }

//    @ExceptionHandler(MethodArgumentNotValidException .class)
//    protected ResponseEntity<Object> handleValidation(MethodArgumentNotValidException  ex) {
//        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
//        apiError.setMessage("Validation error");
//        apiError.addValidationErrors(ex.getBindingResult().getFieldErrors());
//        return buildResponseEntity(apiError);
//    }

    @ExceptionHandler(SQLException.class)
    protected ResponseEntity<Object> handleSQLException(SQLException ex) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("SQL error");
        apiError.addValidationError(ex.getSQLState(), ex.getMessage());
        return buildResponseEntity(apiError);
    }

    @ExceptionHandler(HibernateException.class)
    protected ResponseEntity<Object> handleHibernateException(HibernateException ex) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Hibernate error");
        apiError.addValidationError(ex.getLocalizedMessage());
        return buildResponseEntity(apiError);
    }


    @ExceptionHandler(EmptyResultDataAccessException.class)
    protected ResponseEntity<Object> handleEmptyResultDataAccessException(EmptyResultDataAccessException ex) {
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR);
        apiError.setMessage("Empty result error");
        apiError.addValidationError(ex.getMessage());
        return buildResponseEntity(apiError);
    }

//    // token is null/ not valid
//    @ExceptionHandler(JwtTokenNotValidException.class)
//    protected Mono<ServerResponse> handleTokenNotValidException(ServerWebExchange exchange, JwtTokenNotValidException ex) {
//
//        exchange.getAttributes().putIfAbsent(ErrorAttributes.ERROR_ATTRIBUTE, ex);
//
//        ApiError apiError = new ApiError(HttpStatus.UNAUTHORIZED);
//        apiError.setMessage("Unauthorized");
//        apiError.addValidationError(ex.getMessage());
//        return ServerResponse.from((ServerResponse) apiError).build();
//    }

//    // token is null/ not valid
//    @ExceptionHandler(ErrorWebException.class)
//    protected Mono<ServerResponse> handleTokenNotValidException(ServerWebExchange exchange, ErrorWebException ex) {
//
//        exchange.getAttributes().putIfAbsent(ErrorAttributes.ERROR_ATTRIBUTE, ex);
//
//        ApiError apiError = new ApiError(HttpStatus.UNAUTHORIZED);
//        apiError.setMessage("Unauthorized");
//        apiError.addValidationError(ex.getMessage());
//        return ServerResponse.from((ServerResponse) apiError).build();
//    }


}
