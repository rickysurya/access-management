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