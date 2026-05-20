package com.trustamarket.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/**").permitAll() // 비인가 링크추가하시면됩니다.
                        .pathMatchers("/api/v1/users/signup").permitAll()
                        .pathMatchers("/demo/v1/payments/**").permitAll()
                        .pathMatchers("/api/v1/alerts/**").permitAll()
                        .pathMatchers("/api/v1/admin/inspections/**").hasAnyRole("ADMIN", "INSPECTOR")
                        .pathMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        // Swagger UI aggregation — ADMIN 만 접근. 8 MSA 의 spec 을 한 화면에 토글.
                        .pathMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/webjars/**").hasRole("ADMIN")
                        .anyExchange().authenticated())
                .oauth2ResourceServer(
                        oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));

        return http.build();
    }

    /**
     * Keycloak JWT 토큰의 권한(roles) 정보를 Spring Security의 권한 체계(GrantedAuthority)로 변환하는
     * 컨버터입니다.
     * 기본적으로 Spring Security는 'scope' 클레임을 찾지만, Keycloak은 'realm_access.roles'에 역할을
     * 저장하므로 별도 변환이 필요합니다.
     */
    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        // JWT에서 권한 정보를 추출하는 방식을 커스텀 설정
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // 1. Keycloak 토큰 내 'realm_access' 클레임 추출
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess == null || !realmAccess.containsKey("roles")) {
                return Collections.emptyList();
            }

            // 2. 'roles' 리스트 추출
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");

            // 3. 각 역할을 'ROLE_ADMIN'과 같은 Spring Security 표준 형식으로 변환
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                    .collect(Collectors.toList());
        });

        // WebFlux 기반의 게이트웨이 환경에 맞게 어댑터로 감싸서 반환
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }
}
