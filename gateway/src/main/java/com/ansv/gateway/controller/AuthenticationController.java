package com.ansv.gateway.controller;

import com.ansv.gateway.constants.JwtExceptionEnum;
import com.ansv.gateway.dto.redis.AccessToken;
import com.ansv.gateway.dto.redis.RefreshToken;
import com.ansv.gateway.filter.JwtTokenProvider;
import com.ansv.gateway.constants.MessageConstans;
import com.ansv.gateway.dto.request.LoginRequest;
import com.ansv.gateway.handler.ErrorWebException;
import com.ansv.gateway.security.JwtAuthenticationResponse;
import com.ansv.gateway.security.MessageResponse;
import com.ansv.gateway.service.RedisService;
import com.ansv.gateway.service.UserDetailsServiceImpl;
import com.ansv.gateway.util.DataUtils;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.*;
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

    @Autowired
    private RedisService redisService;

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
            String refreshJwt = null;
            String role = null;
            List<String> permissions = new ArrayList<>();
            String uuid = null;
            String refreshTokenId = null;

            SecurityContextHolder.getContext().setAuthentication(authentication);

            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                if (principal instanceof UserDetails) {
                    uuid = redisService.generateUUIDVersion1();
                    userDetails = (UserDetails) principal;
                    if (userDetails.getUsername().equals("superadmin@ansv.vn")) {
                        role = "ADMIN";
                        permissions.add(role);
//                        jwt = jwtTokenProvider.generateToken(userDetails.getUsername(), role, permissions, uuid);
                        jwt = jwtTokenProvider.generateAccessToken(userDetails.getUsername(), uuid);
                        refreshJwt = jwtTokenProvider.generateRefreshToken(userDetails.getUsername(), uuid);
                    } else {
                        log.info("----SecurityContextHolder getPrincipal UserDetails:" + userDetails.getUsername());
                        if (DataUtils.notNullOrEmpty(userDetails.getAuthorities())) {
                            role = "USER";
                            permissions = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                                    .collect(Collectors.toList());
//                            jwt = jwtTokenProvider.generateToken(userDetails.getUsername(), role, permissions, uuid);
                            jwt = jwtTokenProvider.generateAccessToken(userDetails.getUsername(), uuid);
                            refreshJwt = jwtTokenProvider.generateRefreshToken(userDetails.getUsername(), uuid);

                        }
                    }
                } else {
                    log.info("----SecurityContextHolder getPrincipal UserDetails:"
                            + SecurityContextHolder.getContext().getAuthentication().getPrincipal());
                }
            }

            AccessToken token = AccessToken.builder()
                    .accessToken(jwt)
                    .username(userDetails.getUsername())
                    .uuid(uuid)
                    .expiredTime(jwtTokenProvider.getJwtTokenValidity())
                    .serviceName("taskManagement")
                    .build();

            RefreshToken refreshToken = RefreshToken.builder()
                    .refreshToken(refreshJwt)
                    .username(userDetails.getUsername())
                    .uuid(uuid)
                    .expiredTime(jwtTokenProvider.getJwtRefresTokenValidity())
//                    .expiredTime(6000L)
                    .serviceName("taskManagement")
                    .build();

            redisService.saveAccessToken(token);
            redisService.saveRefreshToken(refreshToken);
//            JwtAuthenticationResponse jwtAuth = new JwtAuthenticationResponse(jwt, userDetails.getUsername(), role);
//            JwtAuthenticationResponse jwtAuth = new JwtAuthenticationResponse(uuid, userDetails.getUsername());
            JwtAuthenticationResponse jwtAuth = new JwtAuthenticationResponse(jwt, userDetails.getUsername(), uuid);
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

    @RequestMapping(value = "/refreshToken", method = RequestMethod.POST)
    public ResponseEntity<?> refreshToken(@RequestHeader String accessToken) {
        try {
            String username = jwtTokenProvider.getUsernameFromToken(accessToken);
            String uuid = jwtTokenProvider.getUUID(accessToken);
            String jwtTokenNew = jwtTokenProvider.generateAccessToken(username, uuid);
            AccessToken token = AccessToken.builder()
                    .accessToken(jwtTokenNew)
                    .username(username)
                    .uuid(uuid)
                    .expiredTime(jwtTokenProvider.getJwtTokenValidity())
                    .serviceName("taskManagement")
                    .build();
            redisService.saveAccessToken(token);
            JwtAuthenticationResponse jwtAuth = new JwtAuthenticationResponse(jwtTokenNew, username, uuid);
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

    @RequestMapping(value = "/refreshTokenClient/{id}", method = RequestMethod.GET)
    public ResponseEntity<?> refreshTokenClient(@PathVariable(value = "id") String uuid) {
        try {

//            String jwt = headers.get("Authorization").substring(7);
            Optional<AccessToken> accessToken = redisService.getAccessToken(uuid);
            String username = null;
            String jwtTokenNew = null;

            if(accessToken.isPresent()) {
                username = accessToken.get().getUsername();
            } else {
                throw new ErrorWebException(HttpStatus.UNAUTHORIZED, JwtExceptionEnum.INVALID_JWT_TOKEN.getName());
            }

            // finding refreshToken
            Optional<RefreshToken> refreshToken = redisService.getRefreshToken(uuid);
            if (refreshToken.isPresent()) {
                boolean isValidate = jwtTokenProvider.validateToken(refreshToken.get().getRefreshToken());

                // neu chua expired
                if (isValidate) {
                    redisService.deleteAccessToken(uuid);

                    // generate new accessToken
                    jwtTokenNew = jwtTokenProvider.generateAccessToken(username, uuid);

                    AccessToken token = AccessToken.builder()
                            .accessToken(jwtTokenNew)
                            .username(username)
                            .uuid(uuid)
                            .expiredTime(jwtTokenProvider.getJwtTokenValidity())
                            .serviceName("taskManagement")
                            .build();
                    redisService.saveAccessToken(token);
                }

            }
            // delete old accessToken

            JwtAuthenticationResponse jwtAuth = new JwtAuthenticationResponse(jwtTokenNew, username, uuid);
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

    @RequestMapping(value = "/signOut", method = RequestMethod.POST)
    public ResponseEntity<?> signOut(@RequestBody AccessToken accessToken) {
        try {
            redisService.deleteAccessToken(accessToken.getUuid());
            redisService.deleteRefreshToken(accessToken.getUuid());
            return ResponseEntity.ok().body(HttpStatus.OK);
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
