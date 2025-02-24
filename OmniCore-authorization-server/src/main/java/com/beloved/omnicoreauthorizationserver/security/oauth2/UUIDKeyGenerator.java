package com.beloved.omnicoreauthorizationserver.security.oauth2;

import org.springframework.security.crypto.keygen.StringKeyGenerator;

import java.util.UUID;


/**
 * uuid生成
 *
 * @author baipengyan
 */
public class UUIDKeyGenerator implements StringKeyGenerator {
    @Override
    public String generateKey() {
        return UUID.randomUUID().toString().toLowerCase();
    }
}

