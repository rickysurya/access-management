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