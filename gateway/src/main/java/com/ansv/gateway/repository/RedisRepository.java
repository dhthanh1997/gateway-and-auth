package com.ansv.gateway.repository;

import com.ansv.gateway.dto.redis.AccessToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.temporal.TemporalUnit;
import java.util.Date;

@Repository
public class RedisRepository {

    private static final Logger logger = LoggerFactory.getLogger(RedisRepository.class);

    private HashOperations hashOperations;

    private RedisTemplate redisTemplate;



    public RedisRepository(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.hashOperations = this.redisTemplate.opsForHash();
    }

    public void saveToken(String jsonToken, String type, String uuid, Date expiredTime) {
        try {
            hashOperations.put(type, uuid, jsonToken);
            this.redisTemplate.expire(uuid, Duration.ofSeconds(60));
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    };

    public void updateToken(String jsonToken, String type, String uuid, Date expiredTime) {
        saveToken(jsonToken, type, uuid, expiredTime);
    };

    public Object getToken(String uuid, String type) {
        return hashOperations.get(type,  uuid);
    };

    public Object getTokenByObject(String uuid, String type) {
        return (Object) hashOperations.get(type,  uuid);
    };

    public void deleteToken(String uuid, String type) {
        hashOperations.delete(type, uuid);
    };

}
