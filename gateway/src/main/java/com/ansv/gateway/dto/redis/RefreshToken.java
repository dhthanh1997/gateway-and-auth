package com.ansv.gateway.dto.redis;

import com.redis.om.spring.annotations.Document;
import com.redis.om.spring.annotations.Indexed;
import com.redis.om.spring.annotations.Searchable;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.io.Serializable;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Data
@Builder
@NoArgsConstructor
@RedisHash(value = "refreshToken")
public class RefreshToken {

    @Id
    private String id;

    @NonNull
    private String refreshToken;

    @NonNull
    private String username;

    private String department;

    private String position;

    @NonNull
    private String uuid;

    @TimeToLive
    @NonNull
    private Date expiredTime;

    @NonNull
    private String serviceName;

}
