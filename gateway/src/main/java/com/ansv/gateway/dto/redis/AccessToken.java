package com.ansv.gateway.dto.redis;

import com.redis.om.spring.annotations.Document;
import com.redis.om.spring.annotations.Indexed;
import com.redis.om.spring.annotations.Searchable;
import com.redis.om.spring.annotations.Document;
import lombok.*;
import org.springframework.beans.factory.annotation.Value;
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
@RedisHash(value = "accessToken")
public class AccessToken implements Serializable {

    @Id
    @Indexed
    private String id;

    //    @Indexed
    private String accessToken;

    @Indexed
    @Searchable
    @NonNull
    private String username;

    @Indexed
    @Searchable
    private String department;

    @Indexed
    @Searchable
    private String position;

//    @Indexed
//    private Set<String> tags = new HashSet<String>();

    @Indexed
    @NonNull
    @Searchable
    private String uuid;

    @Indexed
    @TimeToLive
    @NonNull
    private Date expiredTime;

    @Indexed
    @Searchable
    @NonNull
    private String serviceName;

}
