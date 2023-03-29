package com.ansv.gateway.filter;

import com.ansv.gateway.constants.JwtExceptionEnum;
import com.ansv.gateway.handler.ErrorWebException;
import com.ansv.gateway.handler.JwtTokenNotValidException;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;


@Component
public class JwtTokenProvider {
    private static final long serialVersionUID = -2550185165626007488L;
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private String validateError = new String();


    //   clientId
    @Value("${app.jwtSecret}")
    private String JWT_SECRET;

    @Value("${app.tokenValidity}")
    private long JWT_TOKEN_VALIDITY;


    @Value("${app.refreshTokenValidity}")
    private long JWT_REFRESH_TOKEN_VALIDITY;


    public String getValidateError() {
        return this.validateError;
    }

    public Date getJwtTokenValidity() {
        Date now = new Date();
        return new Date(now.getTime() + JWT_TOKEN_VALIDITY);
    }

    public Date getJwtRefresTokenValidity() {
        Date now = new Date();
        return new Date(now.getTime() + JWT_REFRESH_TOKEN_VALIDITY);
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody();
        return claims.getSubject().toString();
    }

    // using LDAP to authenticate
    public String generateToken(Authentication authentication, String role, List<String> permissions) {
        LdapUserDetailsImpl user = (LdapUserDetailsImpl) authentication.getPrincipal();
        Date now = new Date();
        Date expriryDate = new Date(now.getTime() + JWT_TOKEN_VALIDITY);
        return Jwts.builder().setSubject(user.getUsername()).setIssuedAt(now).setExpiration(expriryDate).signWith(SignatureAlgorithm.HS512, JWT_SECRET).claim("role", role).claim("permissions", permissions).compact();
    }

    public String generateToken(String username, String role, List<String> permissions, String uuid) {
        Date now = new Date();
        Date expriryDate = new Date(now.getTime() + JWT_TOKEN_VALIDITY);
        return Jwts.builder().setSubject(username).setIssuedAt(now).setExpiration(expriryDate).signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .claim("role", role)
                .claim("permissions", permissions)
                .claim("uuid", uuid)
                .compact();
    }

    public String generateAccessToken(String username, String uuid) {
        Date now = new Date();
        Date expriryDate = new Date(now.getTime() + JWT_TOKEN_VALIDITY);
        return Jwts.builder().setSubject(username).setIssuedAt(now).setExpiration(expriryDate).signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .claim("uuid", uuid)
                .compact();
    }


    public String generateRefreshToken(String username, String uuid) {
        Date now = new Date();
        Date expriryDate = new Date(now.getTime() + JWT_REFRESH_TOKEN_VALIDITY);
        return Jwts.builder().setSubject(username).setIssuedAt(now).setExpiration(expriryDate).signWith(SignatureAlgorithm.HS512, JWT_SECRET)
                .claim("uuid", uuid)
                .compact();
    }

    public String generateToken(String uuid) {
        Date now = new Date();
        Date expriryDate = new Date(now.getTime() + JWT_TOKEN_VALIDITY);
        return Jwts.builder().setSubject(uuid).setIssuedAt(now).setExpiration(expriryDate).signWith(SignatureAlgorithm.HS512, JWT_SECRET)
//                .claim("role", role)
//                .claim("permissions", permissions)
//                .claim("uuid", uuid)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature", e);
//            this.validateError = JwtExceptionEnum.INVALID_JWT_SIGNATURE.getName();
            throw new ErrorWebException(HttpStatus.UNAUTHORIZED, JwtExceptionEnum.INVALID_JWT_SIGNATURE.getName());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT Token ");
//            this.validateError = JwtExceptionEnum.INVALID_JWT_TOKEN.getName();
            throw new ErrorWebException(HttpStatus.UNAUTHORIZED, JwtExceptionEnum.INVALID_JWT_TOKEN.getName());
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT Token");
//            this.validateError = JwtExceptionEnum.EXPIRED_JWT_TOKEN.getName();
            throw new ErrorWebException(HttpStatus.UNAUTHORIZED, JwtExceptionEnum.EXPIRED_JWT_TOKEN.getName());
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT Token");
//            this.validateError = JwtExceptionEnum.UNSUPPORT_JWT_TOKEN.getName();
            throw new ErrorWebException(HttpStatus.UNAUTHORIZED, JwtExceptionEnum.UNSUPPORT_JWT_TOKEN.getName());

        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty");
//            this.validateError = JwtExceptionEnum.JWT_CLAIMS_EMPTY.getName();
            throw new ErrorWebException(HttpStatus.UNAUTHORIZED, JwtExceptionEnum.JWT_CLAIMS_EMPTY.getName());

        }
    }

    public String getUUID(String token) {
        Claims claims = Jwts.parser().setSigningKey((JWT_SECRET)).parseClaimsJws(token).getBody();
//        Claims claims = Jwts.parser().parseClaimsJws(token).getBody();
        return claims.get("uuid").toString();
    }


}
