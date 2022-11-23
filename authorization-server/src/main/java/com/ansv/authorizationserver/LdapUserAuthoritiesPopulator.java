package com.ansv.authorizationserver;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Slf4j
@Component
@RequiredArgsConstructor
public class LdapUserAuthoritiesPopulator implements LdapAuthoritiesPopulator {

    private final UserDetailsService userDetailsService;
    private static final Logger logger = LoggerFactory.getLogger(LdapUserAuthoritiesPopulator.class);

    @Override
    public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
        try {
            return userDetailsService.loadUserByUsername(username).getAuthorities();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }
}
