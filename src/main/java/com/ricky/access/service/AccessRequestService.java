package com.ricky.access.service;

import com.ricky.access.domain.*;
import com.ricky.access.repository.AccessRequestRepository;
import com.ricky.access.repository.AuditLogRepository;
import com.ricky.access.repository.UserRepository;
import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AccessRequestService {

    private final AccessRequestRepository accessRequestRepository;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;

    // Constructor injection (Spring will auto-wire these)
    public AccessRequestService(
            AccessRequestRepository accessRequestRepository,
            AuditLogRepository auditLogRepository,
            UserRepository userRepository) {
        this.accessRequestRepository = accessRequestRepository;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
    }

    // Create a new access request
    @Transactional(

    )
    public AccessRequest createRequest(String resource, String justification, String username) {
        // Find the user
        User requester = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        // Create request (domain enforces PENDING status)
        AccessRequest request = new AccessRequest(requester, resource, justification);

        // Save to database
        AccessRequest saved = accessRequestRepository.save(request);

        // Write audit log
        AuditLog log = new AuditLog(
                AuditAction.CREATE_REQUEST,
                "AccessRequest",
                saved.getId(),
                requester
        );
        auditLogRepository.save(log);

        return saved;
    }

    // Approve a request (admin only)
    @Transactional
    public AccessRequest approveRequest(Long requestId, String reviewerUsername) {
        // Find reviewer
        User reviewer = userRepository.findByUsername(reviewerUsername)
                .orElseThrow(() -> new IllegalArgumentException("Reviewer not found: " + reviewerUsername));

        // Check if admin
        if (!reviewer.isAdmin()) {
            throw new SecurityException("Only admins can approve requests");
        }

        // Load request
        AccessRequest request = accessRequestRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Request not found: " + requestId));

        // Domain method enforces business rules
        request.approve(reviewer);

        // Save changes
        AccessRequest updated = accessRequestRepository.save(request);

        // Write audit log
        AuditLog log = new AuditLog(
                AuditAction.APPROVE_REQUEST,
                "AccessRequest",
                requestId,
                reviewer
        );
        auditLogRepository.save(log);

        return updated;
    }

    // Reject a request (admin only)
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

    // Get all requests
    public List<AccessRequest> getAllRequests() {
        return accessRequestRepository.findAll();
    }

    // Get requests for a specific user
    public List<AccessRequest> getMyRequests(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
        return accessRequestRepository.findByRequester(user);
    }

    // Expire old pending requests (for scheduled job later)
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