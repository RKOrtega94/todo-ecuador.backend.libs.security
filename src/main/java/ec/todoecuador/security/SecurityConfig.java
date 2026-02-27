package ec.todoecuador.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.crypto.spec.SecretKeySpec;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfig {
    private final SecurityProperties securityProperties;

    public SecurityConfig(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) {
        http //
                .csrf(AbstractHttpConfigurer::disable) //
                .cors(cors -> cors.configurationSource(corsConfigurationSource)) //
                .formLogin(AbstractHttpConfigurer::disable) //
                .httpBasic(AbstractHttpConfigurer::disable) //
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()) //
                        .accessDeniedHandler((request, response, accessDeniedException) -> response.sendError(403, accessDeniedException.getMessage())) //
                        .authenticationEntryPoint((request, response, authException) -> response.sendError(401, authException.getMessage()))) //
                .exceptionHandling(this::configureExceptionHandling) //
                .authorizeHttpRequests(this::authorizeConfig);
        return http.build();
    }

    private void authorizeConfig(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
        if (securityProperties.getPublicPaths() != null)
            securityProperties.getPublicPaths().forEach(path -> authorize.requestMatchers(path).permitAll());
        if (securityProperties.getPublicGetPaths() != null)
            securityProperties.getPublicGetPaths().forEach(path -> authorize.requestMatchers(HttpMethod.GET, path).permitAll());
        if (securityProperties.getPublicPostPaths() != null)
            securityProperties.getPublicPostPaths().forEach(path -> authorize.requestMatchers(HttpMethod.POST, path).permitAll());
        if (securityProperties.getPublicPutPaths() != null)
            securityProperties.getPublicPutPaths().forEach(path -> authorize.requestMatchers(HttpMethod.PUT, path).permitAll());
        if (securityProperties.getPublicDeletePaths() != null)
            securityProperties.getPublicDeletePaths().forEach(path -> authorize.requestMatchers(HttpMethod.DELETE, path).permitAll());
        authorize.anyRequest().authenticated();
    }

    private void configureExceptionHandling(ExceptionHandlingConfigurer<HttpSecurity> exceptions) {
        exceptions //
                .accessDeniedHandler((request, response, accessDeniedException) -> response.sendError(403, accessDeniedException.getMessage())) //
                .authenticationEntryPoint((request, response, authException) -> response.sendError(401, authException.getMessage()));
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        if (securityProperties.getJwtSigningKey() == null || securityProperties.getJwtSigningKey().isEmpty()) {
            throw new IllegalStateException("JWT signing key must be configured in security.jwtSigningKey");
        }
        return NimbusJwtDecoder.withSecretKey(new SecretKeySpec(securityProperties.getJwtSigningKey().getBytes(), "HmacSHA256")).build();
    }

}
