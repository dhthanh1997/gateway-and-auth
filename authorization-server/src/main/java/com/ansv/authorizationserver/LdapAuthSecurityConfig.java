package com.ansv.authorizationserver;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.servlet.http.HttpServletResponse;
import com.ansv.authorizationserver.LdapUserAuthoritiesPopulator;

// @Profile({Profiles.LDAP_AUTH_DEV, Profiles.LDAP_AUTH_STAGING})
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class LdapAuthSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(LdapAuthSecurityConfig.class);
    private final UserDetailsService userDetailsService;
    private final JwtRequestFilter jwtRequestFilter;
    private final LdapUserAuthoritiesPopulator ldapUserAuthoritiesPopulator;
    private Environment env;

    @Value("${spring.ldap.authen.url:#{null}}")
    private String ldapUrl;

    @Value("${spring.ldap.server.base:#{null}}")
    private String baseDn;

    @Value("${spring.ldap.authen.managerDn:#{null}}")
    private String managerDn;

    @Value("${spring.ldap.authen.managerPassword:#{null}}")
    private String managerPassword;
    @Value("${spring.ldap.authen.dn-patterLdapUserAuthoritiesPopulatorns:#{null}}")
    private String dnPatterns;
    @Value("${spring.ldap.authen.filter:#{null}}")
    private String searchFilter;

    @Value("${spring.ldap.authen.port:#{null}}")
    private Integer port;

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        try {
          
            authenticationManagerBuilder.inMemoryAuthentication().withUser("superadmin@ansv.vn")
                    .password(passwordEncoder().encode("admin@123")).roles("ADMIN");

            authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());


            authenticationManagerBuilder.authenticationProvider(
                    new LdapAuthenticationProvider(env, ldapUrl, baseDn, managerDn,
                            managerPassword, searchFilter, userDetailsService))
                    .eraseCredentials(false);

        } catch (AuthenticationException e) {
            logger.error(e.getMessage(), e);
        }

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
        // enable cors and disable csrf
        http.cors().and().csrf().disable();

        // set session management to stateless
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and();

        // set unauthorized requests exception handler
        http.exceptionHandling().authenticationEntryPoint((request, response, ex) -> {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
        }).and();

        // http.httpBasic();
        // set permission on endpoints
        http.authorizeRequests()
                // public endpoints
                .antMatchers("/").permitAll()
                .antMatchers("/authorization/**").permitAll()
                .antMatchers(HttpMethod.POST, "/authorization/login").permitAll()
                .antMatchers("/authentication/**").permitAll()
                .antMatchers(HttpMethod.POST, "/authentication/login").permitAll()


                // // private endpoints
                // .antMatchers("/api/user/**").permitAll()

                .anyRequest().authenticated()
                // .and()
                // .httpBasic()
                ;

        // add jwt token filter
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

    }

    // @Bean
    // protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    // {
    // // enable cors and disable csrf
    // http.cors().and().csrf().disable();

    // // set session management to stateless
    // http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and();

    // // set unauthorized requests exception handler
    // http.exceptionHandling().authenticationEntryPoint((request, response, ex) ->
    // {
    // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
    // }).and();

    // // set permission on endpoints
    // http.authorizeRequests()
    // // public endpoints
    // // .antMatchers("/").permitAll()
    // .antMatchers("/api/auth/**").permitAll()
    // .antMatchers(HttpMethod.POST, "/api/auth/login").permitAll()

    // // private endpoints
    // .antMatchers("/api/user/**").permitAll()

    // .anyRequest().authenticated();

    // // add jwt token filter
    // http.addFilterBefore(jwtRequestFilter,
    // UsernamePasswordAuthenticationFilter.class);
    // return http.build();
    // }


    @Bean
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
    // @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
