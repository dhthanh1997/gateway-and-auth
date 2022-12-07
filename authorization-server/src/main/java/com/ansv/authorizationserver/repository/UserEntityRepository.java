package com.ansv.authorizationserver.repository;

import com.ansv.authorizationserver.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserEntityRepository extends JpaRepository<UserEntity, Long> {

    UserEntity findByUsername(String username);

}
