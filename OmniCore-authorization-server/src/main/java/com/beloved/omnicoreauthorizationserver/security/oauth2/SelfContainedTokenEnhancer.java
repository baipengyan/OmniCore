package com.beloved.omnicoreauthorizationserver.security.oauth2;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;


/**
 * 透明token扩展
 *
 * @author baipengyan
 */
@Service
public class SelfContainedTokenEnhancer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        context.getClaims().claims(claims -> {
            claims.put("custom1", "透明token扩展");
            claims.put("custom2", "透明token扩展");
        });
    }
}

