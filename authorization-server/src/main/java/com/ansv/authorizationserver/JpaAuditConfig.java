package com.ansv.authorizationserver;


import com.ansv.authorizationserver.constants.Constants;
import com.ansv.authorizationserver.util.DataUtils;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaAuditConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
        String user = getUser();
        return () -> Optional.ofNullable(Optional.ofNullable(user).orElse(ThreadContext.get(Constants.ACTION_USER) != null ? ThreadContext.get(Constants.ACTION_USER) : "UNKOWNS"));
    }

    private String getUser() {
        if (DataUtils.notNull(SecurityContextHolder.getContext().getAuthentication())) {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof UserDetails) {
                return ((UserDetails) principal).getUsername();
            } else {
                return (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            }
        }
        return null;
    }

}
