// package com.ansv.gateway.config;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
// import org.springframework.security.config.web.server.ServerHttpSecurity;
// import org.springframework.security.web.server.SecurityWebFilterChain;

// @Configuration
// @EnableWebFluxSecurity
// public class GatewayConfig {

//     @Bean
//     public SecurityWebFilterChain securityWebFilterChain(
//             ServerHttpSecurity http) {
//                 http.csrf().disable();
//          http.cors().and().httpBasic().and().formLogin().disable();
//          http.authorizeExchange()
//          .anyExchange().authenticated();
                
//                 return http.build();
//     }
// }
