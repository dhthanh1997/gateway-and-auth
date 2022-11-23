package com.ansv.authorizationserver.dto.response;


import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDTO {
    private Long id;

    private String username;

    private String code;

    private String fullName;

    private String email;

    private String phone_number;

    private String position;

    private String note;

    private Long roleId;

    private String password;

}
