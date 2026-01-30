# Access Management System - Complete Source Code

## Table of Contents
1. [Project Overview](#project-overview)
2. [Configuration Files](#configuration-files)
3. [Domain Layer](#domain-layer)
4. [Repository Layer](#repository-layer)
5. [Service Layer](#service-layer)
6. [Controller Layer](#controller-layer)
7. [Security & Config](#security--config)
8. [Scheduled Jobs](#scheduled-jobs)
9. [Exception Handling](#exception-handling)
10. [Database Migration](#database-migration)
11. [README & Setup](#readme--setup)

---

# Project Overview

**Internal Access Management System** - Production-ready Spring Boot application with:
- OAuth2/JWT authentication
- Role-based access control (RBAC)
- Immutable audit logging
- Scheduled automation
- Clean domain-driven architecture

**Tech Stack**: Spring Boot 4.0.1, Java 25, PostgreSQL, OAuth2/JWT, Flyway, Docker

---

# Configuration Files

## pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-parent</artifactId>
       <version>4.0.1</version>
       <relativePath/>
    </parent>
    <groupId>com.ricky.access</groupId>
    <artifactId>access-management</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>access-management</name>
    <description>Internal system for managing access requests, approvals, and audit logging</description>
    
    <properties>
       <java.version>25</java.version>
    </properties>
    
    <dependencies>
       <!-- Spring Boot Starters -->
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-data-jpa</artifactId>
       </dependency>
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-security</artifactId>
       </dependency>
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
       </dependency>
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-validation</artifactId>
       </dependency>
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-webmvc</artifactId>
       </dependency>
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-actuator</artifactId>
       </dependency>

       <!-- Database -->
       <dependency>
          <groupId>org.postgresql</groupId>
          <artifactId>postgresql</artifactId>
          <scope>runtime</scope>
       </dependency>
       
       <!-- Flyway for database migrations -->
       <dependency>
          <groupId>org.flywaydb</groupId>
          <artifactId>flyway-core</artifactId>
       </dependency>
       <dependency>
          <groupId>org.flywaydb</groupId>
          <artifactId>flyway-database-postgresql</artifactId>
       </dependency>
       
       <!-- Lombok -->
       <dependency>
          <groupId>org.projectlombok</groupId>
          <artifactId>lombok</artifactId>
          <optional>true</optional>
       </dependency>
       
       <!-- Testing -->
       <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-test</artifactId>
          <scope>test</scope>
       </dependency>
       <dependency>
          <groupId>org.springframework.security</groupId>
          <artifactId>spring-security-test</artifactId>
          <scope>test</scope>
       </dependency>
    </dependencies>

    <build>
       <plugins>
          <plugin>
             <groupId>org.apache.maven.plugins</groupId>
             <artifactId>maven-compiler-plugin</artifactId>
             <configuration>
                <annotationProcessorPaths>
                   <path>
                      <groupId>org.projectlombok</groupId>
                      <artifactId>lombok</artifactId>
                   </path>
                </annotationProcessorPaths>
             </configuration>
          </plugin>
          <plugin>
             <groupId>org.springframework.boot</groupId>
             <artifactId>spring-boot-maven-plugin</artifactId>
             <configuration>
                <excludes>
                   <exclude>
                      <groupId>org.projectlombok</groupId>
                      <artifactId>lombok</artifactId>
                   </exclude>
                </excludes>
             </configuration>
          </plugin>
       </plugins>
    </build>
</project>
```

## src/main/resources/application.yml

```yaml
spring:
  application:
    name: access-management
  
  datasource:
    url: ${DATABASE_URL:jdbc:postgresql://localhost:5432/access_management}
    username: ${DATABASE_USERNAME:postgres}
    password: ${DATABASE_PASSWORD:postgres}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: 10
      minimum-idle: 5
      connection-timeout: 20000
      idle-timeout: 300000
      max-lifetime: 1200000
  
  jpa:
    hibernate:
      ddl-auto: validate  # Production: use validate, not update
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        use_sql_comments: true
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true
  
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${JWT_ISSUER_URI:https://your-auth-provider.com}
          jwk-set-uri: ${JWT_JWK_SET_URI:https://your-auth-provider.com/.well-known/jwks.json}

server:
  port: ${SERVER_PORT:8080}
  error:
    include-message: always
    include-binding-errors: always
  compression:
    enabled: true
  http2:
    enabled: true

logging:
  level:
    root: INFO
    com.ricky.access: DEBUG
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    org.springframework.security: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
  file:
    name: logs/access-management.log
    max-size: 10MB
    max-history: 30

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: when-authorized
  metrics:
    export:
      prometheus:
        enabled: true

# Custom application properties
app:
  scheduling:
    expiration-days: 30
    cron: "0 0 2 * * *"  # Daily at 2 AM
  security:
    allowed-origins: ${ALLOWED_ORIGINS:http://localhost:3000,http://localhost:8080}
```

## src/main/resources/application-dev.yml

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/access_management
    username: postgres
    password: postgres
  
  jpa:
    hibernate:
      ddl-auto: update  # Dev: auto-create schema
    show-sql: true
  
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8081/realms/dev  # Local Keycloak/Auth server

logging:
  level:
    root: INFO
    com.ricky.access: DEBUG
    org.hibernate.SQL: DEBUG
    org.springframework.security: TRACE

app:
  security:
    allowed-origins: http://localhost:3000,http://localhost:4200
```

## src/main/resources/application-prod.yml

```yaml
spring:
  datasource:
    url: ${DATABASE_URL}
    username: ${DATABASE_USERNAME}
    password: ${DATABASE_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 10
  
  jpa:
    hibernate:
      ddl-auto: validate  # Production: never auto-modify schema
    show-sql: false
    properties:
      hibernate:
        jdbc:
          batch_size: 50
  
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${JWT_ISSUER_URI}
          jwk-set-uri: ${JWT_JWK_SET_URI}

logging:
  level:
    root: WARN
    com.ricky.access: INFO
    org.hibernate.SQL: WARN
    org.springframework.security: INFO
  file:
    name: /var/log/access-management/application.log
    max-size: 50MB
    max-history: 60

server:
  port: ${PORT:8080}
  error:
    include-message: never  # Don't leak error details in prod
    include-binding-errors: never

management:
  endpoints:
    web:
      exposure:
        include: health,metrics,prometheus
  endpoint:
    health:
      show-details: never  # Hide internal details

app:
  security:
    allowed-origins: ${ALLOWED_ORIGINS}
```

## docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: access-management-db
    environment:
      POSTGRES_DB: access_management
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    container_name: access-management-keycloak
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: postgres
      KC_DB_PASSWORD: postgres
      KC_HOSTNAME: localhost
      KC_HTTP_ENABLED: true
    ports:
      - "8081:8080"
    command:
      - start-dev
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health/ready || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  postgres_data:
```

## .env.example

```bash
# Database Configuration (Local Development)
DATABASE_URL=jdbc:postgresql://localhost:5432/access_management
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=postgres

# Database Configuration (Production - override these)
# DATABASE_URL=jdbc:postgresql://prod-db:5432/access_management
# DATABASE_USERNAME=prod_user
# DATABASE_PASSWORD=secure_password

# JWT/OAuth2 Configuration
JWT_ISSUER_URI=https://your-auth-provider.com/realms/your-realm
JWT_JWK_SET_URI=https://your-auth-provider.com/realms/your-realm/protocol/openid-connect/certs

# Application Configuration
SERVER_PORT=8080
SPRING_PROFILES_ACTIVE=dev

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200

# Logging
LOG_LEVEL=INFO
```

## .gitignore

```
# Compiled class files
*.class
*.jar
*.war
*.ear
target/
out/

# Log files
*.log
logs/

# Package Files
*.jar
*.war
*.nar
*.ear
*.zip
*.tar.gz
*.rar

# IDE Files
.idea/
*.iml
*.iws
*.ipr
.vscode/
.eclipse/
.settings/
.classpath
.project
*.swp
*.swo
*~

# OS Files
.DS_Store
Thumbs.db

# Spring Boot
application-local.yml
application-local.properties

# Environment variables
.env
.env.local

# Maven
.mvn/
mvnw
mvnw.cmd

# Gradle
.gradle/
build/

# Database
*.db
*.sqlite

# Temp files
*.tmp
*.bak
*.swp
*~.nib

# Security
*.key
*.pem
*.p12
*.jks
```

---

# Domain Layer

## src/main/java/com/ricky/access/domain/Role.java

```java
package com.ricky.access.domain;

public enum Role {
    USER,
    ADMIN
}
```

## src/main/java/com/ricky/access/domain/RequestStatus.java

```java
package com.ricky.access.domain;

public enum RequestStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED
}
```

## src/main/java/com/ricky/access/domain/AuditAction.java

```java
package com.ricky.access.domain;

public enum AuditAction {
    CREATE_REQUEST,
    APPROVE_REQUEST,
    REJECT_REQUEST,
    AUTO_EXPIRE_REQUEST
}
```

## src/main/java/com/ricky/access/domain/User.java

```java
package com.ricky.access.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String username;
    
    @Column(nullable = false)
    private String email;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<Role> roles = new HashSet<>();
    
    public User(String username, String email) {
        this.username = username;
        this.email = email;
        this.roles.add(Role.USER); // default role
    }
    
    public boolean isAdmin() {
        return roles.contains(Role.ADMIN);
    }
    
    public void addRole(Role role) {
        this.roles.add(role);
    }
}
```

## src/main/java/com/ricky/access/domain/AccessRequest.java

```java
package com.ricky.access.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "access_requests")
@Getter
@NoArgsConstructor
public class AccessRequest {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requester_id", nullable = false)
    private User requester;
    
    @Column(nullable = false)
    private String resource;
    
    @Column(length = 500)
    private String justification;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequestStatus status;
    
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by_id")
    private User reviewedBy;
    
    private LocalDateTime reviewedAt;
    
    // Domain constructor - enforces PENDING status
    public AccessRequest(User requester, String resource, String justification) {
        if (requester == null || resource == null || resource.isBlank()) {
            throw new IllegalArgumentException("Requester and resource are required");
        }
        this.requester = requester;
        this.resource = resource;
        this.justification = justification;
        this.status = RequestStatus.PENDING;
        this.createdAt = LocalDateTime.now();
    }
    
    // Business rule: approve only if pending
    public void approve(User reviewer) {
        if (this.status != RequestStatus.PENDING) {
            throw new IllegalStateException("Cannot approve a request that is not pending");
        }
        if (reviewer == null) {
            throw new IllegalArgumentException("Reviewer cannot be null");
        }
        this.status = RequestStatus.APPROVED;
        this.reviewedBy = reviewer;
        this.reviewedAt = LocalDateTime.now();
    }
    
    // Business rule: reject only if pending
    public void reject(User reviewer) {
        if (this.status != RequestStatus.PENDING) {
            throw new IllegalStateException("Cannot reject a request that is not pending");
        }
        if (reviewer == null) {
            throw new IllegalArgumentException("Reviewer cannot be null");
        }
        this.status = RequestStatus.REJECTED;
        this.reviewedBy = reviewer;
        this.reviewedAt = LocalDateTime.now();
    }
    
    // Business rule: expire only if pending
    public void expire() {
        if (this.status != RequestStatus.PENDING) {
            throw new IllegalStateException("Cannot expire a request that is not pending");
        }
        this.status = RequestStatus.EXPIRED;
    }
}
```

## src/main/java/com/ricky/access/domain/AuditLog.java

```java
package com.ricky.access.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Getter
@NoArgsConstructor
public class AuditLog {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditAction action;
    
    @Column(nullable = false)
    private String entityType;
    
    @Column(nullable = false)
    private Long entityId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "performed_by_id", nullable = false)
    private User performedBy;
    
    @Column(nullable = false)
    private LocalDateTime timestamp;
    
    // Append-only constructor
    public AuditLog(AuditAction action, String entityType, Long entityId, User performedBy) {
        if (action == null || entityType == null || entityId == null || performedBy == null) {
            throw new IllegalArgumentException("All audit log fields are required");
        }
        this.action = action;
        this.entityType = entityType;
        this.entityId = entityId;
        this.performedBy = performedBy;
        this.timestamp = LocalDateTime.now();
    }
}
```

---

# Repository Layer

## src/main/java/com/ricky/access/repository/UserRepository.java

```java
package com.ricky.access.repository;

import com.ricky.access.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

## src/main/java/com/ricky/access/repository/AccessRequestRepository.java

```java
package com.ricky.access.repository;

import com.ricky.access.domain.AccessRequest;
import com.ricky.access.domain.RequestStatus;
import com.ricky.access.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AccessRequestRepository extends JpaRepository<AccessRequest, Long> {
    
    List<AccessRequest> findByRequester(User requester);
    
    List<AccessRequest> findByStatus(RequestStatus status);
    
    @Query("SELECT ar FROM AccessRequest ar WHERE ar.status = :status AND ar.createdAt < :cutoffDate")
    List<AccessRequest> findOldPendingRequests(
        @Param("status") RequestStatus status, 
        @Param("cutoffDate") LocalDateTime cutoffDate
    );
}
```

## src/main/java/com/ricky/access/repository/AuditLogRepository.java

```java
package com.ricky.access.repository;

import com.ricky.access.domain.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    
    List<AuditLog> findByEntityTypeAndEntityId(String entityType, Long entityId);
}
```

---

# Service Layer

## src/main/java/com/ricky/access/service/AccessRequestService.java

```java
package com.ricky.access.service;

import com.ricky.access.domain.*;
import com.ricky.access.repository.AccessRequestRepository;
import com.ricky.access.repository.AuditLogRepository;
import com.ricky.access.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AccessRequestService {
    
    private final AccessRequestRepository accessRequestRepository;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;
    
    public AccessRequestService(
            AccessRequestRepository accessRequestRepository,
            AuditLogRepository auditLogRepository,
            UserRepository userRepository) {
        this.accessRequestRepository = accessRequestRepository;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
    }
    
    @Transactional
    public AccessRequest createRequest(String resource, String justification, String username) {
        User requester = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
        
        AccessRequest request = new AccessRequest(requester, resource, justification);
        AccessRequest saved = accessRequestRepository.save(request);
        
        AuditLog log = new AuditLog(
            AuditAction.CREATE_REQUEST,
            "AccessRequest",
            saved.getId(),
            requester
        );
        auditLogRepository.save(log);
        
        return saved;
    }
    
    @Transactional
    public AccessRequest approveRequest(Long requestId, String reviewerUsername) {
        User reviewer = userRepository.findByUsername(reviewerUsername)
            .orElseThrow(() -> new IllegalArgumentException("Reviewer not found: " + reviewerUsername));
        
        if (!reviewer.isAdmin()) {
            throw new SecurityException("Only admins can approve requests");
        }
        
        AccessRequest request = accessRequestRepository.findById(requestId)
            .orElseThrow(() -> new IllegalArgumentException("Request not found: " + requestId));
        
        request.approve(reviewer);
        AccessRequest updated = accessRequestRepository.save(request);
        
        AuditLog log = new AuditLog(
            AuditAction.APPROVE_REQUEST,
            "AccessRequest",
            requestId,
            reviewer
        );
        auditLogRepository.save(log);
        
        return updated;
    }
    
    @Transactional
    public AccessRequest rejectRequest(Long requestId, String reviewerUsername) {
        User reviewer = userRepository.findByUsername(reviewerUsername)
            .orElseThrow(() -> new IllegalArgumentException("Reviewer not found: " + reviewerUsername));
        
        if (!reviewer.isAdmin()) {
            throw new SecurityException("Only admins can reject requests");
        }
        
        AccessRequest request = accessRequestRepository.findById(requestId)
            .orElseThrow(() -> new IllegalArgumentException("Request not found: " + requestId));
        
        request.reject(reviewer);
        AccessRequest updated = accessRequestRepository.save(request);
        
        AuditLog log = new AuditLog(
            AuditAction.REJECT_REQUEST,
            "AccessRequest",
            requestId,
            reviewer
        );
        auditLogRepository.save(log);
        
        return updated;
    }
    
    public List<AccessRequest> getAllRequests() {
        return accessRequestRepository.findAll();
    }
    
    public List<AccessRequest> getMyRequests(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
        return accessRequestRepository.findByRequester(user);
    }
    
    @Transactional
    public int expireOldRequests(int daysOld) {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(daysOld);
        List<AccessRequest> oldRequests = accessRequestRepository.findOldPendingRequests(
            RequestStatus.PENDING, 
            cutoff
        );
        
        User systemUser = userRepository.findByUsername("system")
            .orElseThrow(() -> new IllegalStateException("System user not found"));
        
        for (AccessRequest request : oldRequests) {
            request.expire();
            accessRequestRepository.save(request);
            
            AuditLog log = new AuditLog(
                AuditAction.AUTO_EXPIRE_REQUEST,
                "AccessRequest",
                request.getId(),
                systemUser
            );
            auditLogRepository.save(log);
        }
        
        return oldRequests.size();
    }
}
```

---

# Controller Layer

## src/main/java/com/ricky/access/dto/CreateRequestDTO.java

```java
package com.ricky.access.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CreateRequestDTO {
    
    @NotBlank(message = "Resource is required")
    @Size(min = 3, max = 200, message = "Resource must be between 3 and 200 characters")
    @Pattern(
        regexp = "^[a-zA-Z0-9-_./]+$", 
        message = "Resource can only contain alphanumeric characters, hyphens, underscores, dots, and slashes"
    )
    private String resource;
    
    @Size(max = 500, message = "Justification cannot exceed 500 characters")
    private String justification;
}
```

## src/main/java/com/ricky/access/dto/AccessRequestResponseDTO.java

```java
package com.ricky.access.dto;

import com.ricky.access.domain.AccessRequest;
import com.ricky.access.domain.RequestStatus;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class AccessRequestResponseDTO {
    
    private Long id;
    private String requesterUsername;
    private String resource;
    private String justification;
    private RequestStatus status;
    private LocalDateTime createdAt;
    private String reviewedByUsername;
    private LocalDateTime reviewedAt;
    
    public static AccessRequestResponseDTO fromEntity(AccessRequest request) {
        AccessRequestResponseDTO dto = new AccessRequestResponseDTO();
        dto.setId(request.getId());
        dto.setRequesterUsername(request.getRequester().getUsername());
        dto.setResource(request.getResource());
        dto.setJustification(request.getJustification());
        dto.setStatus(request.getStatus());
        dto.setCreatedAt(request.getCreatedAt());
        
        if (request.getReviewedBy() != null) {
            dto.setReviewedByUsername(request.getReviewedBy().getUsername());
        }
        dto.setReviewedAt(request.getReviewedAt());
        
        return dto;
    }
}
```

## src/main/java/com/ricky/access/controller/AccessRequestController.java

```java
package com.ricky.access.controller;

import com.ricky.access.domain.AccessRequest;
import com.ricky.access.dto.AccessRequestResponseDTO;
import com.ricky.access.dto.CreateRequestDTO;
import com.ricky.access.service.AccessRequestService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/access-requests")
public class AccessRequestController {
    
    private final AccessRequestService accessRequestService;
    
    public AccessRequestController(AccessRequestService accessRequestService) {
        this.accessRequestService = accessRequestService;
    }
    
    @PostMapping
    public ResponseEntity<AccessRequestResponseDTO> createRequest(
            @Valid @RequestBody CreateRequestDTO dto,
            @AuthenticationPrincipal Jwt jwt) {
        
        String username = extractUsername(jwt);
        
        AccessRequest request = accessRequestService.createRequest(
            dto.getResource(), 
            dto.getJustification(), 
            username
        );
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(AccessRequestResponseDTO.fromEntity(request));
    }
    
    @PostMapping("/{id}/approve")
    public ResponseEntity<AccessRequestResponseDTO> approveRequest(
            @PathVariable Long id,
            @AuthenticationPrincipal Jwt jwt) {
        
        String reviewerUsername = extractUsername(jwt);
        AccessRequest request = accessRequestService.approveRequest(id, reviewerUsername);
        return ResponseEntity.ok(AccessRequestResponseDTO.fromEntity(request));