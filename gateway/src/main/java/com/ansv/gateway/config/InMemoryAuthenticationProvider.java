package com.ansv.gateway.config;

import com.ansv.gateway.dto.mapper.UserMapper;
import com.ansv.gateway.dto.response.UserDTO;
import com.ansv.gateway.service.CustomUserDetailService;
import com.ansv.gateway.service.rabbitmq.RabbitMqSender;
import com.ansv.gateway.util.DataUtils;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
@Slf4j
//@RequiredArgsConstructor
@NoArgsConstructor
public class InMemoryAuthenticationProvider implements AuthenticationProvider {

    private String username;
    private String password;

    private CustomUserDetailService customUserDetailService;

    @Autowired
    private RabbitMqSender rabbitMqSender;

    public InMemoryAuthenticationProvider(String username, String password, UserDetailsService userDetailsService) {
        this.username = username;
        this.password = password;
        this.customUserDetailService = (CustomUserDetailService) userDetailsService;
        this.rabbitMqSender = new RabbitMqSender();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            final String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDER" : authentication.getName();
            UserDetails userDetails = customUserDetailService.loadUserByUsernameForInmemoryAuth(username, authentication.getCredentials().toString());
            Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, authentication.getCredentials().toString(), new ArrayList<>());
            return auth;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    private static List<SimpleGrantedAuthority> buildSimpleGrantedAuthorities(final List<String> roles) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }
}
