package org.example.secshare.auth;

import org.example.secshare.auth.dto.RegisterRequest;
import org.example.secshare.auth.dto.LoginRequest;
import org.example.secshare.auth.dto.AuthResponse;
import org.example.secshare.user.User;
import org.example.secshare.user.UserRepository;
import org.example.secshare.vuln.VulnProperties;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class AuthService {

    /** Guvenli modda (vuln.auth.no-rate-limit=false) izin verilen ardisik hatali deneme. */
    private static final int MAX_ATTEMPTS = 5;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final VulnProperties vuln;

    // basit in-memory deneme sayaci (yalnizca guvenli mod icin)
    private final ConcurrentHashMap<String, AtomicInteger> failedAttempts = new ConcurrentHashMap<>();

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       VulnProperties vuln) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.vuln = vuln;
    }

    public void register(RegisterRequest request) {
        boolean exists = userRepository.existsByEmailIgnoreCase(request.email());

        if (exists) {
            if (userEnumEnabled()) {
                // VULN: kayitli email'i acikca ele verir (user enumeration)
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
            }
            // Guvenli: varligi sizdirmadan sessizce cik (idempotent gorunum)
            return;
        }

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(request.email().toLowerCase());
        user.setPasswordHash(passwordEncoder.encode(request.password()));

        // VULN (mass assignment): client'in gonderdigi roles dogrudan atanir.
        if (massAssignmentEnabled() && request.roles() != null && !request.roles().isBlank()) {
            user.setRoles(request.roles());
        } else {
            user.setRoles("USER");
        }
        user.setCreatedAt(Instant.now());

        userRepository.save(user);
    }

    public AuthResponse login(LoginRequest request) {
        String email = request.email();

        // Rate limit yalnizca guvenli modda uygulanir.
        if (!noRateLimitEnabled() && attemptsFor(email).get() >= MAX_ATTEMPTS) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many attempts");
        }

        Optional<User> maybeUser = userRepository.findByEmailIgnoreCase(email);

        if (maybeUser.isEmpty()) {
            recordFailure(email);
            if (userEnumEnabled()) {
                // VULN: kullanici yoksa 404 -> gecerli email'ler ayirt edilebilir
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
            }
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        User user = maybeUser.get();

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            recordFailure(email);
            if (userEnumEnabled()) {
                // VULN: sifre yanlissa 401 "Invalid password" -> email dogru demektir
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password");
            }
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        failedAttempts.remove(email.toLowerCase());

        // Rolleri DB'deki degerden uret (mass assignment ile ADMIN atanmis olabilir).
        List<String> roles = Arrays.stream(user.getRoles().split("[,\\s]+"))
                .map(String::trim)
                .filter(r -> !r.isEmpty())
                .toList();
        if (roles.isEmpty()) {
            roles = List.of("USER");
        }

        String token = jwtService.generateToken(user.getId(), user.getEmail(), roles);

        return new AuthResponse(token);
    }

    private boolean userEnumEnabled() {
        return vuln.isEnabled() && vuln.getAuth().isUserEnum();
    }

    private boolean noRateLimitEnabled() {
        return vuln.isEnabled() && vuln.getAuth().isNoRateLimit();
    }

    private boolean massAssignmentEnabled() {
        return vuln.isEnabled() && vuln.getAuth().isMassAssignment();
    }

    private AtomicInteger attemptsFor(String email) {
        return failedAttempts.computeIfAbsent(email.toLowerCase(), k -> new AtomicInteger(0));
    }

    private void recordFailure(String email) {
        if (!noRateLimitEnabled()) {
            attemptsFor(email).incrementAndGet();
        }
    }
}
