package com.beloved.omnicoreauthorizationserver.security.oauth2;

import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;


/**
 * 不透明token扩展
 *
 * @author baipengyan
 */
@Service
public class ReferenceTokenEnhancer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        context.getClaims().claims(claims -> {
            claims.put("custom3", "不透明token扩展");
            claims.put("custom4", "不透明token扩展");
        });
    }
}

