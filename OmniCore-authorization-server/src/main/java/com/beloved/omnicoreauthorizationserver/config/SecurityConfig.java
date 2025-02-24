package com.beloved.omnicoreauthorizationserver.config;

import com.beloved.omnicoreauthorizationserver.security.oauth2.ReferenceTokenEnhancer;
import com.beloved.omnicoreauthorizationserver.security.oauth2.SelfContainedTokenEnhancer;
import com.beloved.omnicoreauthorizationserver.security.oauth2.password.OAuth2PasswordAuthenticationConverter;
import com.beloved.omnicoreauthorizationserver.security.oauth2.password.OAuth2PasswordAuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * @author baipengyan
 */
@Configuration
public class SecurityConfig {
    private final JdbcTemplate jdbcTemplate;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    private final SelfContainedTokenEnhancer selfContainedTokenEnhancer;
    private final ReferenceTokenEnhancer referenceTokenEnhancer;

    private final OAuth2PasswordAuthenticationConverter oAuth2PasswordAuthenticationConverter;
    private final OAuth2PasswordAuthenticationProvider oAuth2PasswordAuthenticationProvider;

    public SecurityConfig(JdbcTemplate jdbcTemplate,
                          @Lazy UserDetailsService userDetailsService,
                          @Lazy PasswordEncoder passwordEncoder,
                          @Lazy SelfContainedTokenEnhancer selfContainedTokenEnhancer,
                          @Lazy ReferenceTokenEnhancer referenceTokenEnhancer,
                          @Lazy OAuth2PasswordAuthenticationConverter oAuth2PasswordAuthenticationConverter,
                          @Lazy OAuth2PasswordAuthenticationProvider oAuth2PasswordAuthenticationProvider) {
        this.jdbcTemplate = jdbcTemplate;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.selfContainedTokenEnhancer = selfContainedTokenEnhancer;
        this.referenceTokenEnhancer = referenceTokenEnhancer;
        this.oAuth2PasswordAuthenticationConverter = oAuth2PasswordAuthenticationConverter;
        this.oAuth2PasswordAuthenticationProvider = oAuth2PasswordAuthenticationProvider;
    }

    /**
     * 启动时生成的密钥，用于创建上面的JWKSource
     *
     * @return {@link KeyPair }
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                ).oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()))
                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .accessTokenRequestConverter(oAuth2PasswordAuthenticationConverter)
                                .authenticationProvider(oAuth2PasswordAuthenticationProvider)
                        )
                );
        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .authenticationManager(authenticationManager(http));
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    /**
     * 用于密码加密
     *
     * @return {@link PasswordEncoder }
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 用于签署访问令牌
     *
     * @return {@link JWKSource }<{@link SecurityContext }>
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(authenticationProvider())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * 用于解码签名访问令牌
     *
     * @param jwkSource JSON Web 密钥 （JWK） 源
     * @return {@link JwtDecoder }
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(selfContainedTokenEnhancer);
        // 不透明的token生成器
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(referenceTokenEnhancer);
        // refreshToken生成器
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        /*// 不透明的token生成器
        UUIDOAuth2TokenGenerator accessTokenGenerator = new UUIDOAuth2TokenGenerator();
        // refreshToken生成器
        UUIDOAuth2RefreshTokenGenerator refreshTokenGenerator = new UUIDOAuth2RefreshTokenGenerator();*/

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }


    /**
     * 用于配置 Spring Authorization Server
     *
     * @return {@link AuthorizationServerSettings }
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}