package com.ansv.gateway;

//import com.redis.om.spring.annotations.EnableRedisDocumentRepositories;

import com.ansv.gateway.repository.redis.RedisTokenRepository;
import com.redis.om.spring.annotations.EnableRedisDocumentRepositories;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
@EnableRedisDocumentRepositories(basePackageClasses = {RedisTokenRepository.class})
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

}
