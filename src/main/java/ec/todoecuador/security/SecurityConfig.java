package ec.todoecuador.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfig {
    private static final String DEFAULT_AUTH_SERVER_ISSUER = "http://localhost:9000";

    private final SecurityProperties securityProperties;

    public SecurityConfig(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http //
                .csrf(AbstractHttpConfigurer::disable) //
                .cors(Customizer.withDefaults()) //
                .formLogin(AbstractHttpConfigurer::disable) //
                .httpBasic(AbstractHttpConfigurer::disable) //
                .requestCache(AbstractHttpConfigurer::disable) //
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder()).jwtAuthenticationConverter(jwtAuthenticationConverter()))) //
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint()).accessDeniedHandler(new BearerTokenAccessDeniedHandler())) //
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

    @Bean
    public JwtDecoder jwtDecoder() {
        String issuer = securityProperties.getIssuerUri();
        if (issuer == null || issuer.isBlank()) issuer = DEFAULT_AUTH_SERVER_ISSUER;
        log.info("Configuring JWT decoder with authorization server issuer: {}", issuer);
        return NimbusJwtDecoder.withIssuerLocation(issuer).build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("authorities");
        authoritiesConverter.setAuthorityPrefix("");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
