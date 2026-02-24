package org.example.secshare.auth;

import org.example.secshare.auth.security.UserPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/token")
    public String token(@RequestParam String email) {
        return jwtService.generateToken(new UserPrincipal(UUID.randomUUID(), email));
    }
}