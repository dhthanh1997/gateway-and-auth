package com.ansv.gateway.security;

import com.ansv.gateway.util.DataUtils;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.ansv.gateway.constants.Constants.JWT_AUTH_TOKEN_VALIDITY;

@Data
public class JwtAuthenticationResponse {


    private String accessToken;
    private String tokenType = "Bearer";
    private boolean success = false;
    private JwtTokenResponse tokenResponse;
    private String username;
    // private UserDetails user;
    private List<String> role;
    private List<String> permissions;

    public String getAccessToken() {
        return this.accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return this.tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isSuccess() {
        return this.success;
    }

    public boolean getSuccess() {
        return this.success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public JwtTokenResponse getTokenResponse() {
        return this.tokenResponse;
    }

    public void setTokenResponse(JwtTokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRole() {
        return this.role;
    }

    public void setRole(List<String> role) {
        this.role = role;
    }

    public List<String> getPermissions() {
        return this.permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }


    public JwtAuthenticationResponse(String accessToken, UserDetails userDetails) {
        this.accessToken = accessToken;
        JwtTokenResponse tokenResponse = new JwtTokenResponse();
        tokenResponse.setAccessToken(accessToken);
        tokenResponse.setExpiresIn(JWT_AUTH_TOKEN_VALIDITY);
        this.success = true;
        // this.user = userDetails;
        if (userDetails != null) {
            this.username = userDetails.getUsername();
            if (DataUtils.notNullOrEmpty(userDetails.getAuthorities())) {
                role = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());
                permissions = role;
            }
        }
    }

    public JwtAuthenticationResponse(String accessToken, String username, String role) {
        this.accessToken = accessToken;
        JwtTokenResponse tokenResponse = new JwtTokenResponse();
        tokenResponse.setAccessToken(accessToken);
        tokenResponse.setExpiresIn(JWT_AUTH_TOKEN_VALIDITY);
        this.success = true;
        this.username = username;
        this.role = Arrays.asList(role);
        this.permissions = Arrays.asList(role);

    }
}
