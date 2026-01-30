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