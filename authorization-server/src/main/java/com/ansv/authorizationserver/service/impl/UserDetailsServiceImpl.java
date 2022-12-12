package com.ansv.authorizationserver.service.impl;

import com.ansv.authorizationserver.dto.mapper.UserMapper;
import com.ansv.authorizationserver.dto.response.UserDTO;
import com.ansv.authorizationserver.model.UserEntity;
import com.ansv.authorizationserver.repository.UserEntityRepository;
import com.ansv.authorizationserver.util.DataUtils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.naming.ldap.LdapContext;
import java.util.ArrayList;
import java.util.List;


@Service
@Slf4j
public class UserDetailsServiceImpl implements CustomUserDetailService {

    @Autowired
    private UserEntityRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);

        User newUser = null;
        if (user != null) {
            if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
                throw new UsernameNotFoundException("User not found with username: ");
            }

            newUser = new User(user.getUsername(), user.getEmail(), buildSimpleGrantedAuthorities("user"));
        } else {
            //            creating if user isn't exist in db
            log.warn("User not found with username ----> create in db", username);
            user = new UserEntity();
            user.setUsername(username);
            user.setStatus("ACTIVE");
            userRepository.save(user);
            newUser = new User(user.getUsername(), user.getEmail(), buildSimpleGrantedAuthorities("user"));
            return newUser;
        }
        return newUser;
    }

    private static List<SimpleGrantedAuthority> buildSimpleGrantedAuthorities(final List<String> roles, List<String> roleList) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
//         for (Role role : roles) {
//             authorities.add(new SimpleGrantedAuthority(role.getName()));
//         }
        if (DataUtils.notNullOrEmpty(roleList)) {
            for (String role : roleList) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
        }
        return authorities;
    }

    private static List<SimpleGrantedAuthority> buildSimpleGrantedAuthorities(String role) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (DataUtils.isNullOrEmpty(role)) {
            role = "user";
        }
        authorities.add(new SimpleGrantedAuthority(role));
        return authorities;

    }


    @Override
    public UserDetails loadUser(String username, String displayName, String email) {
        UserEntity user = userRepository.findByUsername(username);
        User newUser = null;
        if (user != null) {
            if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
                throw new UsernameNotFoundException("User not found with username: ");
            }

            newUser = new User(user.getUsername(), user.getEmail(), buildSimpleGrantedAuthorities("user"));
        } else {
            //            creating if user isn't exist in db
            log.warn("User not found with username ----> create in db", username);
            user = new UserEntity();
            user.setUsername(username);
            user.setEmail(email);
            user.setFullname(displayName);
            user.setStatus("ACTIVE");
            userRepository.save(user);
            newUser = new User(username, email, buildSimpleGrantedAuthorities("user"));
            return newUser;
        }
        return newUser;
    }

    @Override
    public UserDTO findByUsername(String username) {
        UserEntity entity = userRepository.findByUsername(username);
        UserDTO dto = UserMapper.INSTANCE.modelToDTO(entity);
        return dto;
    }
}
