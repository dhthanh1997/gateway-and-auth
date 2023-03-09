package com.ansv.gateway.formatdate;

import com.ansv.gateway.util.DataUtils;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

@Slf4j
public class LocalDateTimeDeserializer extends JsonDeserializer<LocalDateTime> {

    public static final String YYYY_MM_DD_HH_MM_SS = "yyyy-MM-dd HH:mm:ss";
    public static final String YYYY_MM_DD_T_HH_MM_SS = "yyyy-MM-dd'T'HH:mm:ss";
    public static final String YYYY_MM_DD_FULL = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

    @Override
    public LocalDateTime deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        String str = jsonParser.getText();
        try {
            return convertStringToLocalDateTime(str, YYYY_MM_DD_T_HH_MM_SS);
        } catch (DateTimeParseException e) {
            log.error(e.getMessage(), e);
            return deserialize(str);
        }
    }


    private LocalDateTime deserialize(String value) {
        try {
            return convertStringToLocalDateTime(value, YYYY_MM_DD_HH_MM_SS);
        } catch (DateTimeParseException e) {
            log.error(e.getMessage(), e);
            return deserialize2(value);
        }
    }

    private LocalDateTime deserialize2(String value) {
        try {
           return convertStringToLocalDateTime(value, YYYY_MM_DD_FULL);
        } catch (DateTimeParseException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public static LocalDateTime convertStringToLocalDateTime(String value, String format) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        if (DataUtils.isNullOrEmpty(value)) {
            return null;
        } else if (value.contains(".")) {
            value = value.substring(0, value.indexOf('.'));
        }
        LocalDateTime formatDateTime = LocalDateTime.parse(value, formatter);
        return formatDateTime;
    }
}
