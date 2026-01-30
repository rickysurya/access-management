# ACCESS MANAGEMENT SYSTEM - COMPLETE CODE BUNDLE
## Production-Ready Spring Boot Application with OAuth2/JWT

```
================================================================================
                    QUICK REFERENCE - PROJECT STRUCTURE
================================================================================

access-management/
├── pom.xml
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
└── src/
    ├── main/
    │   ├── java/com/ricky/access/
    │   │   ├── AccessManagementApplication.java
    │   │   ├── domain/
    │   │   │   ├── User.java
    │   │   │   ├── AccessRequest.java
    │   │   │   ├── AuditLog.java
    │   │   │   ├── Role.java (enum)
    │   │   │   ├── RequestStatus.java (enum)
    │   │   │   └── AuditAction.java (enum)
    │   │   ├── repository/
    │   │   │   ├── UserRepository.java
    │   │   │   ├── AccessRequestRepository.java
    │   │   │   └── AuditLogRepository.java
    │   │   ├── service/
    │   │   │   └── AccessRequestService.java
    │   │   ├── controller/
    │   │   │   └── AccessRequestController.java
    │   │   ├── dto/
    │   │   │   ├── CreateRequestDTO.java
    │   │   │   └── AccessRequestResponseDTO.java
    │   │   ├── config/
    │   │   │   ├── SecurityConfig.java
    │   │   │   └── SchedulerConfig.java
    │   │   ├── security/
    │   │   │   └── JwtUtil.java
    │   │   ├── scheduled/
    │   │   │   └── ExpireOldRequestsJob.java
    │   │   ├── bootstrap/
    │   │   │   └── DataLoader.java
    │   │   └── exception/
    │   │       └── GlobalExceptionHandler.java
    │   └── resources/
    │       ├── application.yml
    │       ├── application-dev.yml
    │       ├── application-prod.yml
    │       └── db/migration/
    │           └── V1__initial_schema.sql
    └── test/
        └── java/com/ricky/access/

================================================================================
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 1: pom.xml
## ═══════════════════════════════════════════════════════════════════════════

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         https://maven.apache.org/xsd/maven-4.0.0.xsd">
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
    <description>Internal access management with OAuth2/JWT and audit logging</description>
    
    <properties>
        <java.version>25</java.version>
    </properties>
    
    <dependencies>
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
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-database-postgresql</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
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
            </plugin>
        </plugins>
    </build>
</project>
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 2: docker-compose.yml
## ═══════════════════════════════════════════════════════════════════════════

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
    command: start-dev
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres_data:
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 3: .env.example
## ═══════════════════════════════════════════════════════════════════════════

```bash
# Local Development
DATABASE_URL=jdbc:postgresql://localhost:5432/access_management
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=postgres

# Production (override these)
# DATABASE_URL=jdbc:postgresql://prod-server:5432/access_management
# DATABASE_USERNAME=prod_user
# DATABASE_PASSWORD=your_secure_password

# JWT Configuration
JWT_ISSUER_URI=http://localhost:8081/realms/dev
JWT_JWK_SET_URI=http://localhost:8081/realms/dev/protocol/openid-connect/certs

# Application
SERVER_PORT=8080
SPRING_PROFILES_ACTIVE=dev
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 4: src/main/resources/application.yml
## ═══════════════════════════════════════════════════════════════════════════

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
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        jdbc:
          batch_size: 20
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${JWT_ISSUER_URI}
          jwk-set-uri: ${JWT_JWK_SET_URI}

server:
  port: ${SERVER_PORT:8080}
  compression:
    enabled: true

logging:
  level:
    root: INFO
    com.ricky.access: DEBUG
  file:
    name: logs/access-management.log
    max-size: 10MB

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus

app:
  scheduling:
    expiration-days: 30
    cron: "0 0 2 * * *"
  security:
    allowed-origins: ${ALLOWED_ORIGINS:http://localhost:3000}
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 5: src/main/resources/application-dev.yml
## ═══════════════════════════════════════════════════════════════════════════

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8081/realms/dev

logging:
  level:
    com.ricky.access: DEBUG
    org.springframework.security: TRACE
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 6: src/main/resources/application-prod.yml
## ═══════════════════════════════════════════════════════════════════════════

```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 20
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
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
  file:
    name: /var/log/access-management/application.log
    max-size: 50MB

server:
  error:
    include-message: never
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 7: src/main/resources/db/migration/V1__initial_schema.sql
## ═══════════════════════════════════════════════════════════════════════════

```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE access_requests (
    id BIGSERIAL PRIMARY KEY,
    requester_id BIGINT NOT NULL,
    resource VARCHAR(255) NOT NULL,
    justification VARCHAR(500),
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    reviewed_by_id BIGINT,
    reviewed_at TIMESTAMP,
    FOREIGN KEY (requester_id) REFERENCES users(id),
    FOREIGN KEY (reviewed_by_id) REFERENCES users(id)
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100) NOT NULL,
    entity_id BIGINT NOT NULL,
    performed_by_id BIGINT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (performed_by_id) REFERENCES users(id)
);

CREATE INDEX idx_access_requests_requester ON access_requests(requester_id);
CREATE INDEX idx_access_requests_status ON access_requests(status);
CREATE INDEX idx_access_requests_created_at ON access_requests(created_at);
CREATE INDEX idx_audit_logs_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);

INSERT INTO users (username, email) VALUES 
    ('system', 'system@company.com'),
    ('admin', 'admin@company.com');

INSERT INTO user_roles (user_id, role) VALUES 
    (1, 'ADMIN'),
    (2, 'ADMIN');
```

---

## ═══════════════════════════════════════════════════════════════════════════
## FILE 8: src/main/java/com/ricky/access/AccessManagementApplication.java
## ═══════════════════════════════════════════════════════════════════════════

```java
package com.ricky.access;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AccessManagementApplication {
    public static void main(String[] args) {
        SpringApplication.run(AccessManagementApplication.class, args);
    }
}
```

---

## ═══════════════════════════════════════════════════════════════════════════
## DOMAIN LAYER - Enums
## ═══════════════════════════════════════════════════════════════════════════

### FILE 9: src/main/java/com/ricky/access/domain/Role.java
```java
package com.ricky.access.domain;

public enum Role {
    USER,
    ADMIN
}
```

### FILE 10: src/main/java/com/ricky/access/domain/RequestStatus.java
```java
package com.ricky.access.domain;

public enum RequestStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED
}
```

### FILE 11: src/main/java/com/ricky/access/domain/AuditAction.java
```java
package com.ricky.access.domain;

public enum AuditAction {
    CREATE_REQUEST,
    APPROVE_REQUEST,
    REJECT_REQUEST,
    AUTO_EXPIRE_REQUEST
}
```

---

## ═══════════════════════════════════════════════════════════════════════════
## DOMAIN LAYER - Entities
## ═══════════════════════════════════════════════════════════════════════════

### FILE 12: src/main/java/com/ricky/access/domain/User.java
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
        this.roles.add(Role.USER);
    }
    
    public boolean isAdmin() {
        return roles.contains(Role.ADMIN);
    }
    
    public void addRole(Role role) {
        this.roles.add(role);
    }
}
```

### FILE 13: src/main/java/com/ricky/access/domain/AccessRequest.java
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
    
    public void expire() {
        if (this.status != RequestStatus.PENDING) {
            throw new IllegalStateException("Cannot expire a request that is not pending");
        }
        this.status = RequestStatus.EXPIRED;
    }
}
```

### FILE 14: src/main/java/com/ricky/access/domain/AuditLog.java
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

## ═══════════════════════════════════════════════════════════════════════════
## REPOSITORY LAYER
## ═══════════════════════════════════════════════════════════════════════════

### FILE 15: src/main/java/com/ricky/access/repository/UserRepository.java
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

### FILE 16: src/main/java/com/ricky/access/repository/AccessRequestRepository.java
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

### FILE 17: src/main/java/com/ricky/access/repository/AuditLogRepository.java
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

## ═══════════════════════════════════════════════════════════════════════════
## SERVICE LAYER
## ═══════════════════════════════════════════════════════════════════════════

### FILE 18: src/main/java/com/ricky/access/service/AccessRequestService.java
```java
package com.ricky.access.service;

import com.ricky.access.domain.*;
import com.ricky.access.repository.*;
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
        
        AuditLog log = new AuditLog(AuditAction.CREATE_REQUEST, "AccessRequest", saved.getId(), requester);
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
        
        AuditLog log = new AuditLog(AuditAction.APPROVE_REQUEST, "AccessRequest", requestId, reviewer);
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
        
        AuditLog log = new AuditLog(AuditAction.REJECT_REQUEST, "AccessRequest", requestId, reviewer);
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
            RequestStatus.PENDING, cutoff
        );
        
        User systemUser = userRepository.findByUsername("system")
            .orElseThrow(() -> new IllegalStateException("System user not found"));
        
        for (AccessRequest request : oldRequests) {
            request.expire();
            accessRequestRepository.save(request);
            
            AuditLog log = new AuditLog(AuditAction.AUTO_EXPIRE_REQUEST, "AccessRequest", 
                request.getId(), systemUser);
            auditLogRepository.save(log);
        }
        
        return oldRequests.size();
    }
}
```

---

## ═══════════════════════════════════════════════════════════════════════════
## DTOs
## ═══════════════════════════════════════════════════════════════════════════

### FILE 19: src/main/java/com/ricky/access/dto/CreateRequestDTO.java
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
    @Pattern(regexp = "^[a-zA-Z0-9-_./]+$", 
        message = "Resource can only contain alphanumeric characters, hyphens, underscores, dots, and slashes")
    private String resource;
    
    @Size(max = 500, message = "Justification cannot exceed 500 characters")
    private String justification;
}
```

### FILE 20: src/main/java/com/ricky/access/dto/AccessRequestResponseDTO.java
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
        dto.setStatus(