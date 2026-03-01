package org.example.secshare.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())

                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/health", "/healthz").permitAll()
                    .requestMatchers("/api/auth/**").permitAll()
                    .requestMatchers("/", "/index.html").permitAll()
                    .requestMatchers("/favicon.ico", "/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg", "/**/*.svg").permitAll()
                    .requestMatchers("/error").permitAll()
                    .requestMatchers("/files.html").hasRole("ADMIN")
                    .requestMatchers("/api/files/all").hasRole("ADMIN")
        
                    .requestMatchers("/h2-console/**").permitAll()
                    .requestMatchers("/test.html").permitAll()
                    .anyRequest().authenticated()
                )

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)

                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}