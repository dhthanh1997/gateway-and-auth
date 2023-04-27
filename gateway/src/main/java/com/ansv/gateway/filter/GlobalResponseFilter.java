//package com.ansv.gateway.filter;
//
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.cloud.gateway.filter.GatewayFilterChain;
//import org.springframework.cloud.gateway.filter.GlobalFilter;
//import org.springframework.core.Ordered;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//@Component
//@RequiredArgsConstructor
//@Slf4j
//public class GlobalResponseFilter implements GlobalFilter, Ordered {
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//
//        return chain.filter(exchange).then(Mono.fromRunnable(()->{
//            var response = exchange.getResponse();
////            response.setRawStatusCode(201);
//            exchange.mutate().response(response).build();
//        }));
//    }
//
//    @Override
//    public int getOrder() {
//        return -1;
//    }
//}
