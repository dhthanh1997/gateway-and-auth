package com.ansv.gateway.filter;

import com.ansv.gateway.config.RouterValidator;
import com.ansv.gateway.constants.JwtExceptionEnum;
import com.ansv.gateway.dto.redis.AccessToken;
import com.ansv.gateway.dto.redis.RefreshToken;
import com.ansv.gateway.handler.JwtTokenNotValidException;
import com.ansv.gateway.service.RedisService;
import com.ansv.gateway.service.UserDetailsServiceImpl;
import com.ansv.gateway.util.DataUtils;
import com.ansv.gateway.util.JwtTokenUtil;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.nullness.Opt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.ContentCachingResponseWrapper;
import reactor.core.publisher.Mono;

import javax.persistence.Access;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter implements GlobalFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final JwtTokenUtil jwtTokenUtil;
    private final RedisService redisService;

    @Autowired
    private RouterValidator routerValidator;//custom route validator

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

//        boolean authorization = request.getHeaders().containsKey("Authorization");

        if (routerValidator.isSecured.test(request)) {
            if (!this.isAuthMissing(request)) {
                return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);
            }
            final String token = this.getAuthInHeader(request);
            // check token valid in header
            String username = new String();
            String jwtToken = new String();
            String uuid = new String();
            URI urlRedirectRefreshToken = URI.create("/auth/refreshToken");


            if (token != null) {
                if (token.startsWith("Bearer")) {
                    jwtToken = token.substring(7);
                    boolean isValidated = jwtTokenProvider.validateToken(jwtToken);
                    username = jwtTokenProvider.getUsernameFromToken(jwtToken);
                    uuid = jwtTokenProvider.getUUID(jwtToken);
//                    if (!isValidated) {
//                        if(this.jwtTokenProvider.getValidateError().equals(JwtExceptionEnum.EXPIRED_JWT_TOKEN)) {
//                            throw new JwtTokenNotValidException("JWT token is expired");
//                        }
//                    }

                }
            } else {
                log.warn("JWT token does not begin with Bearer string");
            }


            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null) {
                Object principal = authentication.getPrincipal();
                if (principal instanceof UserDetails) {
                    log.info("------SecurityContextHolder getPrincipal UserDetails:" + ((UserDetails) principal).getUsername());
                } else {
                    log.info("------SecurityContextHolder getPrincipal :" + principal);
                }
            }

            // Once we get the token validate it.
            if (username != null && (authentication == null || "anonymousUser".equals(authentication.getPrincipal()))) {
                UserDetails userDetails = this.userDetailsServiceImpl.loadUserByUsername(username);
                // if token is valid configure Spring Security to manually set authentication
                if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    // After setting the authentication in the context, we specify that
                    // the current user is authenticated. So it passes the Spring security
                    // configuration sucessfully
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                } else {
                    // check if refreshtoken
                    if (request.getURI().equals("/auth/refreshTokenClient") && userDetails.getUsername().equals(username)) {
                        Optional<AccessToken> accessToken = redisService.getAccessToken(uuid);
                        Optional<RefreshToken> refreshToken = redisService.getRefreshToken(uuid);
                        if (accessToken.isPresent() && refreshToken.isPresent()) {
                            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                        }
                    }
                }

            }
        }
        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthInHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty("Authorization").get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return request.getHeaders().containsKey("Authorization");
    }


}
