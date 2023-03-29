package com.ansv.gateway.handler;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.jsontype.impl.TypeIdResolverBase;

public class LowerCaseClassNameResolver extends TypeIdResolverBase {
    @Override
    public String idFromValue(Object o) {
        return o.getClass().getSimpleName().toLowerCase();
    }

    @Override
    public String idFromValueAndType(Object o, Class<?> aClass) {
        return idFromValue(o);
    }

    @Override
    public JsonTypeInfo.Id getMechanism() {
        return JsonTypeInfo.Id.CUSTOM;
    }
}
