package com.ansv.gateway.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;


@Configuration
public class GatewayCorsConfig extends CorsConfiguration {

  

    @Bean
    public CorsWebFilter corsWebFilter() {

        final CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        corsConfig.setMaxAge(3600L);
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));

        corsConfig.addAllowedHeader("Content-Type");
        corsConfig.addAllowedHeader("Origin");
        corsConfig.addAllowedHeader("Accept");
        corsConfig.addAllowedHeader("Cookie");
        corsConfig.addAllowedHeader("Authorization");

        corsConfig.setAllowCredentials(true);

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
}
