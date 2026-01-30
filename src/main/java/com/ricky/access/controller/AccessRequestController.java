package com.ricky.access.controller;

import com.ricky.access.domain.AccessRequest;
import com.ricky.access.dto.AccessRequestResponseDTO;
import com.ricky.access.dto.CreateRequestDTO;
import com.ricky.access.service.AccessRequestService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    // Create new access request
    @PostMapping
    public ResponseEntity<AccessRequestResponseDTO> createRequest(
            @Valid @RequestBody CreateRequestDTO dto,
            @RequestHeader("X-User") String username) {

        AccessRequest request = accessRequestService.createRequest(
                dto.getResource(),
                dto.getJustification(),
                username
        );
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(AccessRequestResponseDTO.fromEntity(request));
    }

    // Approve a request
    @PostMapping("/{id}/approve")
    public ResponseEntity<AccessRequestResponseDTO> approveRequest(
            @PathVariable Long id,
            @RequestHeader("X-User") String reviewerUsername) {

        AccessRequest request = accessRequestService.approveRequest(id, reviewerUsername);
        return ResponseEntity.ok(AccessRequestResponseDTO.fromEntity(request));
    }

    // Reject a request
    @PostMapping("/{id}/reject")
    public ResponseEntity<AccessRequestResponseDTO> rejectRequest(
            @PathVariable Long id,
            @RequestHeader("X-User") String reviewerUsername) {

        AccessRequest request = accessRequestService.rejectRequest(id, reviewerUsername);
        return ResponseEntity.ok(AccessRequestResponseDTO.fromEntity(request));
    }

    // Get all requests (admin view)
    @GetMapping
    public ResponseEntity<List<AccessRequestResponseDTO>> getAllRequests() {
        List<AccessRequestResponseDTO> responses = accessRequestService.getAllRequests()
                .stream()
                .map(AccessRequestResponseDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(responses);
    }

    // Get my requests
    @GetMapping("/mine")
    public ResponseEntity<List<AccessRequestResponseDTO>> getMyRequests(
            @RequestHeader("X-User") String username) {

        List<AccessRequestResponseDTO> responses = accessRequestService.getMyRequests(username)
                .stream()
                .map(AccessRequestResponseDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(responses);
    }
}