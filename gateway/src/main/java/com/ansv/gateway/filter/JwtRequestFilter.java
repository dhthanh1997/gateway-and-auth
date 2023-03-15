package com.ansv.gateway.filter;

import com.ansv.gateway.util.JwtTokenUtil;
import com.ansv.gateway.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.ContentCachingResponseWrapper;
import reactor.core.publisher.Mono;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// @Profile({Profiles.LDAP_AUTH_DEV, Profiles.LDAP_AUTH_STAGING})
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String requestToken = request.getHeader("Authorization");
        long startTime = System.currentTimeMillis();
        String reqUri = request.getRequestURI();
        String method = request.getMethod();

        if (reqUri.startsWith("/ws")) {
            ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper((HttpServletResponse) response);
            filterChain.doFilter(request, responseWrapper);
            responseWrapper.copyBodyToResponse();
            return;
        }

        String username = null;
        String jwtToken = null;

        if (requestToken != null) {
            if (requestToken.startsWith("Bearer")) {
                jwtToken = requestToken.substring(7);
                username = jwtTokenProvider.getUsernameFromToken(jwtToken);
            } else {
                logger.warn("JWT token does not begin with Bearer string");
            }
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                logger.info("------SecurityContextHolder getPrincipal UserDetails:" + ((UserDetails) principal).getUsername());
            } else {
                logger.info("------SecurityContextHolder getPrincipal :" + principal);
            }
        }

        // Once we get the token validate it.
        if (username != null && (authentication == null || "anonymousUser".equals((String) authentication.getPrincipal()))) {
            UserDetails userDetails = this.userDetailsServiceImpl.loadUserByUsername(username);
            // if token is valid configure Spring Security to manually set authentication
            if(jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // After setting the authentication in the context, we specify that
                // the current user is authenticated. So it passes the Spring security
                // configuration sucessfully
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        ContentCachingResponseWrapper responseCacheWrapperObject = new ContentCachingResponseWrapper((HttpServletResponse) response);
        filterChain.doFilter(request, responseCacheWrapperObject);
        // copy body to response
        responseCacheWrapperObject.copyBodyToResponse();

    }

}
