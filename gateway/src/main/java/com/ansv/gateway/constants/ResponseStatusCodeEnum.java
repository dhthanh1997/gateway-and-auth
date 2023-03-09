package com.ansv.gateway.constants;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.Serializable;

@Getter
@AllArgsConstructor
public enum ResponseStatusCodeEnum implements Serializable {

    SUCCESS("00", 200),
    ERROR("ERR200", 200),
    BUSSINESS_ERROR("BUS200", 200),
    INTERNAL_GENERAL_SERVER_ERROR("INTERNAL", 500),
    UNKNOWN("UNKNOWN", 500);

    private String code;
    private String messageKey;
    private int httpCode;

    ResponseStatusCodeEnum(String code, int httpCode) {
        this.code = code;
        this.httpCode = httpCode;
    }

    @Override
    public String toString() {
        return "ResponseStatus {" + "code='" + code + '\'' + "httpCode='" + httpCode + '\'' + '}';
    }

    public void setMessageKey(String message) {
        this.messageKey = message;
    }

    // get code in enum
    public static ResponseStatusCodeEnum getByCode(String code, ResponseStatusCodeEnum defaultValue) {
        for(ResponseStatusCodeEnum res: values()) {
            if(res.code.equals(code)) {
                return res;
            }
        }
        return defaultValue;
    }

    // get code with enum
    public static ResponseStatusCodeEnum getByCode(String code, String messageKey, ResponseStatusCodeEnum defaultValue) {
        for(ResponseStatusCodeEnum res : values()) {
            if(res.code.equals(code)) {
                res.setMessageKey(messageKey);
                return res;
            }
        }
        return defaultValue;
    }
}
