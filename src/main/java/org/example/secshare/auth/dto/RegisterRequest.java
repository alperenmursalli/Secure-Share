package org.example.secshare.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @Email @NotBlank String email,
        @NotBlank @Size(min = 8, max = 72) String password,
        // VULN (vuln.auth.mass-assignment): client bu alani gonderirse rol
        // olarak atanabilir. Guvenli modda yok sayilir.
        String roles
) {}