package com.trustamarket.apigateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Set<String> ALLOWED_ROLES = Set.of("ADMIN", "INSPECTOR", "MEMBER");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // ① JWT 유무와 관계없이 X-User-* 헤더 항상 제거 (spoofing 방지)
        ServerHttpRequest stripped = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.remove("Authorization");
                    headers.remove("X-User-UUID");
                    headers.remove("X-User-Email");
                    headers.remove("X-User-Role");
                    headers.remove("X-User-Name");
                    headers.remove("X-User-Slack-Id");
                    headers.remove("X-User-Enabled");
                })
                .build();

        ServerWebExchange strippedExchange = exchange.mutate()
                .request(stripped)
                .build();

        // ② 검증된 JWT에서 유저 정보를 추출하여 내부 라우팅용 헤더에 재주입 (MSA 내부 통신용)
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .map(Authentication::getPrincipal)
                .filter(principal -> principal instanceof Jwt)
                .cast(Jwt.class)
                .map(jwt -> {
                    ServerHttpRequest.Builder requestBuilder = strippedExchange.getRequest().mutate();
                    
                    // 1. 유저 고유 식별자(UUID) 주입
                    if (jwt.getSubject() != null) {
                        requestBuilder.header("X-User-UUID", jwt.getSubject());
                    }
                    
                    // 2. 유저 이메일 주입
                    String email = jwt.getClaimAsString("email");
                    if (email != null) {
                        requestBuilder.header("X-User-Email", email);
                    }
                    
                    // 3. 유저 권한(Role) 추출 및 Spring Security 규칙(ROLE_ 접두사)에 맞게 변환하여 주입
                    Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                    if (realmAccess != null && realmAccess.containsKey("roles")) {
                        Object rolesObj = realmAccess.get("roles");
                        if (rolesObj instanceof List) {
                            @SuppressWarnings("unchecked")
                            List<String> roles = (List<String>) rolesObj;
                            String roleString = roles.stream()
                                    .map(String::toUpperCase)
                                    .filter(ALLOWED_ROLES::contains)
                                    .map(r -> "ROLE_" + r)
                                    .collect(Collectors.joining(","));
                            if (!roleString.isEmpty()) {
                                requestBuilder.header("X-User-Role", roleString);
                            }
                        }
                    }
                    
                    // 4. 유저 이름 주입 (한글 등 비-ASCII 문자 깨짐 방지를 위해 UTF-8 URL 인코딩 적용)
                    String name = jwt.getClaimAsString("name");
                    if (name != null) {
                        String encodedName = URLEncoder.encode(name, StandardCharsets.UTF_8);
                        requestBuilder.header("X-User-Name", encodedName);
                    }
                    
                    // 5. 알림 및 연동을 위한 Slack ID 주입
                    String slackId = jwt.getClaimAsString("slack_id");
                    if (slackId != null) {
                        requestBuilder.header("X-User-Slack-Id", slackId);
                    }
                    
                    // 6. 계정 활성화 상태 주입
                    Boolean enabled = jwt.getClaimAsBoolean("enabled");
                    if (enabled == null) {
                        enabled = true; //나중에 맞출 부분: 운영 환경(Keycloak 관리자 페이지)에서 Protocol Mappers 설정을 통해 JWT 토큰 자체에 "enabled": true 항목이 포함되도록 세팅

                    }
                    // 7. 결정된 값을 무조건 헤더에 주입 (if문 밖으로 꺼냄)
                    requestBuilder.header("X-User-Enabled", enabled.toString());
                    return strippedExchange.mutate().request(requestBuilder.build()).build();
                })
                .defaultIfEmpty(strippedExchange)
                .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
