package com.ansv.gateway.controller;

import com.ansv.gateway.filter.JwtTokenProvider;
import com.ansv.gateway.constants.MessageConstans;
import com.ansv.gateway.dto.request.LoginRequest;
import com.ansv.gateway.security.JwtAuthenticationResponse;
import com.ansv.gateway.security.MessageResponse;
import com.ansv.gateway.service.UserDetailsServiceImpl;
import com.ansv.gateway.util.DataUtils;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/auth")
@NoArgsConstructor
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    // @ResponseBody
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest) {
        if (loginRequest.getUsername().isEmpty() || loginRequest.getPassword().isEmpty()) {
            return new ResponseEntity(new MessageResponse(false, MessageConstans.USERNAME_OR_PASSWORD_EMPTY),
                    HttpStatus.BAD_REQUEST);
        }
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()));
//            Authentication authentication =

            List<String> permission = new ArrayList<>();
            UserDetails userDetails = null;
            Map<String, Object> mapper = null;
            String jwt = null;
            String role = null;
            List<String> permissions = new ArrayList<>();

            SecurityContextHolder.getContext().setAuthentication(authentication);

            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                if (principal instanceof UserDetails) {
                    userDetails = (UserDetails) principal;
                    if (userDetails.getUsername().equals("superadmin@ansv.vn")) {
                        role = "ADMIN";
                        permissions.add(role);
                        jwt = jwtTokenProvider.generateToken(userDetails.getUsername(), role, permissions);
                    } else {
                        log.info("----SecurityContextHolder getPrincipal UserDetails:" + userDetails.getUsername());
                        if (DataUtils.notNullOrEmpty(userDetails.getAuthorities())) {
                            role = "USER";
                            permissions = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                                    .collect(Collectors.toList());
                            jwt = jwtTokenProvider.generateToken(userDetails.getUsername(), role, permissions);
                        }
                    }
                } else {
                    log.info("----SecurityContextHolder getPrincipal UserDetails:"
                            + SecurityContextHolder.getContext().getAuthentication().getPrincipal());
                }
            }
            JwtAuthenticationResponse jwtAuth = new JwtAuthenticationResponse(jwt, userDetails.getUsername(), role);
            return ResponseEntity.ok().body(jwtAuth);

        } catch (BadCredentialsException e) {
            log.error(e.getMessage(), e);
            return new ResponseEntity(new MessageResponse(false, MessageConstans.USERNAME_OR_PASSWORD_INVALID),
                    HttpStatus.BAD_REQUEST);

        } catch (UsernameNotFoundException e) {
            log.error(e.getMessage(), e);
            return new ResponseEntity(new MessageResponse(false, MessageConstans.USERNAME_INACTIVE),
                    HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return new ResponseEntity(new MessageResponse(false, MessageConstans.SYSTEM_ERROR), HttpStatus.BAD_REQUEST);
        }
    }
}
