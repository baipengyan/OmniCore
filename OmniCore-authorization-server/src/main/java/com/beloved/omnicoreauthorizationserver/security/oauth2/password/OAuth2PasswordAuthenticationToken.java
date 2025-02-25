package com.beloved.omnicoreauthorizationserver.security.oauth2.password;

import com.beloved.omnicoreauthorizationserver.security.oauth2.CustomAuthorizationGrantType;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;


/**
 * 用户名密码令牌扩展
 *
 * @author baipengyan
 */
@Getter
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final String password;

    public OAuth2PasswordAuthenticationToken(String username,
                                             String password,
                                             Authentication clientPrincipal,
                                             Map<String, Object> additionalParameters) {
        super(CustomAuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
    }

}

