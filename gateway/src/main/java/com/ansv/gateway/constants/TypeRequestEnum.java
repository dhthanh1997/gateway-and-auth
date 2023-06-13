package com.ansv.gateway.constants;

public enum TypeRequestEnum {
    INSERT("insert"),
    UPDATE("update"),
    VIEW("view"),
    DELETE("delete");

    final String typeValue;

    TypeRequestEnum(String typeValue) {
        this.typeValue = typeValue;
    }

    @Override
    public String toString() {
        return name();
    }

    public String getName() {
        return name();
    }

    public String getValue() {
        return typeValue;
    }
}
