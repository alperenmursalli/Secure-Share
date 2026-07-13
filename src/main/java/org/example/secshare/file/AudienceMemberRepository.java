package org.example.secshare.file;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AudienceMemberRepository extends JpaRepository<AudienceMember, UUID> {

    long countByAudience_Id(UUID audienceId);

    /** True when {@code email} is a member of any of the given audiences (case-insensitive). */
    boolean existsByAudience_IdInAndEmailIgnoreCase(Collection<UUID> audienceIds, String email);

    Optional<AudienceMember> findByToken(String token);

    List<AudienceMember> findByAudience_IdOrderByEmailAsc(UUID audienceId);
}
