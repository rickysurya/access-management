# Phase 2: Domain Models

Create these 6 files in `src/main/java/com/ricky/access/domain/`

---

## File 1: Role.java
```java
package com.ricky.access.domain;

public enum Role {
    USER,
    ADMIN
}
```

---

## File 2: RequestStatus.java
```java
package com.ricky.access.domain;

public enum RequestStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED
}
```

---

## File 3: AuditAction.java
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

## File 4: User.java
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

---

## File 5: AccessRequest.java
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

---

## File 6: AuditLog.java
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

## Test Phase 2

After creating these 6 files, restart your app:

```powershell
mvn spring-boot:run
```

**You should see in the logs:**
```
Hibernate: create table users ...
Hibernate: create table access_requests ...
Hibernate: create table audit_logs ...
```

**This means Hibernate created your database tables automatically!**

Check your database:
```powershell
docker exec -it access-management-db psql -U postgres -d access_management

# Inside PostgreSQL:
\dt

# You should see:
# users
# user_roles
# access_requests
# audit_logs
```

Type `\q` to exit PostgreSQL.

---

✅ If you see the tables created → Tell me, and I'll give you Phase 3 (Repositories)  
❌ If you get errors → Paste them here
