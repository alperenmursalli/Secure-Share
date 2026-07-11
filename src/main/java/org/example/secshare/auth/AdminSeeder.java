package org.example.secshare.auth;

import org.example.secshare.user.User;
import org.example.secshare.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * Creates an administrator account on startup from environment configuration.
 *
 * Set ADMIN_EMAIL and ADMIN_PASSWORD (e.g. in the deployment env) to bootstrap
 * the first admin. If either is blank, seeding is skipped. If a user with that
 * email already exists, it is left untouched (the password is never overwritten).
 * The password is BCrypt-hashed; it is never stored or logged in plain text.
 */
@Component
public class AdminSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminSeeder.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminEmail;
    private final String adminPassword;

    public AdminSeeder(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.admin.email:}") String adminEmail,
            @Value("${app.admin.password:}") String adminPassword
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminEmail = adminEmail;
        this.adminPassword = adminPassword;
    }

    @Override
    public void run(String... args) {
        if (adminEmail == null || adminEmail.isBlank()
                || adminPassword == null || adminPassword.isBlank()) {
            log.info("Admin seeding skipped (ADMIN_EMAIL/ADMIN_PASSWORD not set).");
            return;
        }

        String email = adminEmail.trim().toLowerCase();

        if (userRepository.existsByEmailIgnoreCase(email)) {
            log.info("Admin account '{}' already exists; leaving it unchanged.", email);
            return;
        }

        User admin = new User();
        admin.setId(UUID.randomUUID());
        admin.setEmail(email);
        admin.setPasswordHash(passwordEncoder.encode(adminPassword));
        admin.setRoles("ADMIN,USER");
        admin.setCreatedAt(Instant.now());

        userRepository.save(admin);
        log.info("Seeded administrator account '{}'.", email);
    }
}
