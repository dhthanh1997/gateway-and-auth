package com.ansv.authorizationserver;

import com.ansv.authorizationserver.service.impl.CustomUserDetailService;
import com.ansv.authorizationserver.service.impl.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.ArrayList;
import java.util.List;


@Component
@Slf4j
@RequiredArgsConstructor
public class LdapAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticationProvider.class);

    private Environment environment;

    private CustomUserDetailService customUserDetailService;

    private String ldapUrl;
    private String base;

    private String managerDn;

    private String managerPassword;

    private String filter;

    public String username;

    public String password;

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return this.username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return this.password;
    }

    private LdapContextSource contextSource;
    private LdapTemplate ldapTemplate;


    private void initContext() {
        contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setUserDn(managerDn);
        contextSource.setPassword(managerPassword);
        contextSource.afterPropertiesSet();
        ldapTemplate = new LdapTemplate(contextSource);
    }

    public LdapAuthenticationProvider(Environment environment, String ldapUrl, String dnPatterns, String managerDn,
                                      String managerPassword, String filter, UserDetailsService userDetailsService) {
        this.environment = environment;
        this.ldapUrl = ldapUrl;
        this.managerDn = managerDn;
        this.managerPassword = managerPassword;
        this.filter = filter;
        this.base = dnPatterns;
        this.customUserDetailService = (CustomUserDetailService) userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        initContext();
        Filter filterLdap = new EqualsFilter(filter, authentication.getPrincipal().toString());

        SearchScope searchScope = SearchScope.SUBTREE;
        LdapQuery query = LdapQueryBuilder.query().base(base).searchScope(searchScope).filter(filterLdap);

        try {

          ldapTemplate.authenticate(query, authentication.getCredentials().toString());
            List<CustomUserDetails> users = ldapTemplate.search(query, new AttributesMapper() {
                public CustomUserDetails mapFromAttributes(Attributes attributes) throws NamingException {
                    CustomUserDetails user = new CustomUserDetails();
                    user.setUsername((String) attributes.get("sAMAccountName").get());
                    user.setDisplayName((String) attributes.get("displayName").get());
                    user.setEmail((String) attributes.get("userPrincipalName").get());
                    return user;
                }
            });

            UserDetails userDetails = customUserDetailService.loadUser(users.get(0).getUsername(), users.get(0).getDisplayName(), users.get(0).getEmail());
            Authentication auth = new UsernamePasswordAuthenticationToken(userDetails,
                    authentication.getCredentials().toString(), new ArrayList<>());
            return auth;
        } catch (Exception e) {
            //TODO: handle exception
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
