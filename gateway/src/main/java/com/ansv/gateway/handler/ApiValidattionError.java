package com.ansv.gateway.handler;

import com.ansv.gateway.util.DataUtils;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
//@AllArgsConstructor
public class ApiValidattionError extends ApiSubError {
    private String object;
    private String field;
    private Object rejectValue;
    private String message;

    public ApiValidattionError(String object, String message) {
        this.object = object;
        this.message = message;
    }

    public ApiValidattionError(String object) {
        this.object = object;
    }

    public ApiValidattionError(String object, String field, Object rejectValue, String message) {
        this.object = object;
        this.message = message;
        this.field = field;
        this.rejectValue = (DataUtils.notNull(rejectValue)) ? rejectValue : "null";
    }

}
