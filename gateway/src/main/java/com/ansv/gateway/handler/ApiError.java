package com.ansv.gateway.handler;


import com.ansv.gateway.util.DataUtils;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
import lombok.Data;
import org.hibernate.validator.internal.engine.path.PathImpl;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

import javax.validation.ConstraintViolation;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Data
@JsonTypeInfo(include = JsonTypeInfo.As.WRAPPER_OBJECT, use = JsonTypeInfo.Id.CUSTOM, property = "error", visible = true)
@JsonTypeIdResolver(com.ansv.gateway.handler.LowerCaseClassNameResolver.class)
public class ApiError {
    private HttpStatus status;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
    private LocalDateTime timestamp;
    private String message;
    private String debugMessage;
    private String detailMessage;
    private List<ApiSubError> subErrors;

    public ApiError() {
        this.timestamp = LocalDateTime.now();
    }

    public ApiError(HttpStatus httpStatus) {
        this.status = httpStatus;
    }

    public ApiError(HttpStatus httpStatus, Throwable ex) {
        this();
        this.status = httpStatus;
        this.message = "Unexpected error";
        this.debugMessage = ex.getLocalizedMessage();
//        this.detailMessage = ex.getMessage();
    }

    public ApiError(HttpStatus httpStatus, String message, Throwable ex) {
        this();
        this.status = httpStatus;
        this.message = message;
        this.debugMessage = ex.getLocalizedMessage();
    }

    private void addSubErrors(ApiSubError error) {
        this.subErrors = new ArrayList<>();
        if (DataUtils.notNull(error)) {
            this.subErrors.add(error);
        }
    }

    private void addValidationError(String object, String field, Object rejectValue, String message) {
        addSubErrors(new ApiValidattionError(object, field, rejectValue, message));
    }

    protected void addValidationError(String object, String message) {
        addSubErrors(new ApiValidattionError(object, message));
    }

    /**
     * using for SQL exception
     * @param object
     */
    protected void addValidationError(String object) {
        addSubErrors(new ApiValidattionError(object));
    }

    private void addValidationError(FieldError fieldError) {

        this.addValidationError(fieldError.getObjectName()
                , fieldError.getField()
                , fieldError.getRejectedValue()
                , fieldError.getDefaultMessage());
    }

    protected void addValidationErrors(List<FieldError> fieldErrors) {
        fieldErrors.forEach(this::addValidationError);
    }

    protected void addValidationError(ObjectError objectError) {
        if (DataUtils.notNull(objectError)) {
            this.addValidationError(objectError.getObjectName(), objectError.getDefaultMessage());
        }
    }


    /**
     * Utility method for adding error of ConstraintViolation. Usually when a @Validated validation fails.
     *
     * @param constraintViolation
     */

    private void addValidationError(ConstraintViolation<?> constraintViolation) {
        this.addValidationError(
                constraintViolation.getRootBeanClass().getSimpleName(),
                ((PathImpl) constraintViolation.getPropertyPath()).getLeafNode().asString(),
                constraintViolation.getInvalidValue(),
                constraintViolation.getMessage()
        );
    }

    public void addValidationErrors(Set<ConstraintViolation<?>> constraintViolations) {
        constraintViolations.forEach(this::addValidationError);
    }


}
