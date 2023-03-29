package com.ansv.gateway.repository.redis;


import com.ansv.gateway.dto.redis.AccessToken;
//import com.redis.om.spring.repository.RedisDocumentRepository;
import com.redis.om.spring.repository.RedisDocumentRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

//@Repository
public interface RedisTokenRepository extends RedisDocumentRepository<AccessToken, String> {
//public interface RedisTokenRepository extends JpaRepository<AccessToken, String> {

    Optional<AccessToken> findOneByUsername(String name);
    Optional<AccessToken> findOneByUuid(String uuid);




}
