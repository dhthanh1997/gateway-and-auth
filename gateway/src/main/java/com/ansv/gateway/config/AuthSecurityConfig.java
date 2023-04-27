package com.ansv.gateway.config;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class AuthSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(AuthSecurityConfig.class);
    private final UserDetailsService userDetailsService;
    private Environment env;

    @Autowired
    private LdapAuthenticationProvider ldapAuthenticationProvider;

    @Value("${app.admin.username:#{null}}")
    private String username;

    @Value("${app.admin.password:#{null}}")
    private String password;

    @Value("${spring.ldap.authen.url:#{null}}")
    private String ldapUrl;

    @Value("${spring.ldap.server.base:#{null}}")
    private String baseDn;

    @Value("${spring.ldap.authen.managerDn:#{null}}")
    private String managerDn;

    @Value("${spring.ldap.authen.managerPassword:#{null}}")
    private String managerPassword;
    @Value("${spring.ldap.authen.dn-pattern:#{null}}")
    private String dnPatterns;
    @Value("${spring.ldap.authen.filter:#{null}}")
    private String searchFilter;

    @Value("${spring.ldap.authen.port:#{null}}")
    private Integer port;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.csrf(csrf -> csrf.disable());
        http.cors();
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/ignore1", "/ignore2");
    }


    @Bean
    @Primary
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return encodedPassword.equals(rawPassword.toString());
            }
        };
    }


    @Bean
    public AuthenticationManager customAuthenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

//            authenticationManagerBuilder.authenticationProvider(ldapAuthenticationProvider);

        authenticationManagerBuilder.authenticationProvider(new LdapAuthenticationProvider(env, ldapUrl, baseDn, managerDn,
                managerPassword, searchFilter, userDetailsService));

        authenticationManagerBuilder.inMemoryAuthentication()
                .withUser(username)
                .password(bCryptPasswordEncoder().encode(password))
                .roles("ADMIN");

        authenticationManagerBuilder.eraseCredentials(false);

        return authenticationManagerBuilder.build();
    }


    @Bean(name = "mvcHandlerMappingIntrospector")
    public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
        return new HandlerMappingIntrospector();
    }


    @Bean
    public UserDetailsService users() {
        UserDetails superadmin = User.builder()
                .username(username)
                .password(bCryptPasswordEncoder().encode(password))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(superadmin);
    }

}
