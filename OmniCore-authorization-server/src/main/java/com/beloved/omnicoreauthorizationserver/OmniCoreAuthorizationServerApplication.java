package com.beloved.omnicoreauthorizationserver;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author baipengyan
 */
@MapperScan(basePackages = {"com.beloved.omnicoreauthorizationserver.mapper"})
@SpringBootApplication
public class OmniCoreAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(OmniCoreAuthorizationServerApplication.class, args);
    }

}
