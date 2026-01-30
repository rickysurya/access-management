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