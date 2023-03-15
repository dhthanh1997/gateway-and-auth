package com.ansv.gateway.formatdate;

import com.ansv.gateway.util.DataUtils;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

@Slf4j
public class LocalDateTimeSerializer extends JsonSerializer<LocalDateTime> {

    public static final String YYYY_MM_DD_T_HH_MM_SS = "yyyy-MM-dd'T' HH:mm:ss";

    @Override
    public void serialize(LocalDateTime localDateTime, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        try {
            String resultFormat = localDateTimeToString(localDateTime, YYYY_MM_DD_T_HH_MM_SS);
            jsonGenerator.writeString(resultFormat);

        } catch (DateTimeParseException e) {
            log.error(e.getMessage(), e);
            jsonGenerator.writeString("");
        }


    }

    public static String localDateTimeToString(LocalDateTime value, String format) {
        if (DataUtils.isNullOrEmpty(value)) {
            return null;
        }
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(YYYY_MM_DD_T_HH_MM_SS);
        return value.format((formatter));

    }
}
