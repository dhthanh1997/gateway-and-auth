package com.ansv.authorizationserver.dto.mapper;

import com.ansv.authorizationserver.dto.response.UserDTO;
import com.ansv.authorizationserver.model.UserEntity;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper
public interface UserMapper {

    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    @Mapping(source = "id", target="id")
    @Mapping(source = "username", target="username")
//    @Mapping(source = "code", target="code")
    @Mapping(source = "fullname", target="fullName")
    @Mapping(source = "email", target="email")
    @Mapping(source = "phone", target="phone_number")
//    @Mapping(source = "roleId", target="roleId")
    @Mapping(source = "departmentId", target="departmentId")
//    @Mapping(source = "password", target="password")
    UserDTO modelToDTO(UserEntity userEntity);
}
