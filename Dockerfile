# syntax=docker/dockerfile:1.7

# ──────────────────────────────────────────────────────────────
# Builder — Gradle 로 bootJar 생성
# ──────────────────────────────────────────────────────────────
FROM gradle:8.10-jdk21-alpine AS builder
WORKDIR /workspace

COPY settings.gradle build.gradle ./
COPY gradle ./gradle
RUN gradle dependencies --no-daemon

COPY src ./src

RUN gradle bootJar --no-daemon \
 && cp build/libs/*.jar /workspace/app.jar

# ──────────────────────────────────────────────────────────────
# Runtime — JRE 만 포함한 경량 이미지
# ──────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Non-root 실행 — UID 1000 (K8s securityContext.runAsUser 와 일치).
RUN addgroup -g 1000 -S spring && adduser -u 1000 -S spring -G spring

COPY --from=builder --chown=spring:spring /workspace/app.jar /app/app.jar

USER spring:spring

EXPOSE 8080

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
