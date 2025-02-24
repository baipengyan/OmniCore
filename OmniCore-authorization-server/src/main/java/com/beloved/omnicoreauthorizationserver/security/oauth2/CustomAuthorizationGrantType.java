package com.beloved.omnicoreauthorizationserver.security.oauth2;

import org.springframework.security.oauth2.core.AuthorizationGrantType;


/**
 * 扩展GrantType类型
 *
 * @author baipengyan
 */
public record CustomAuthorizationGrantType(String value) {
    /**
     * 账号密码模式
     */
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");
}

