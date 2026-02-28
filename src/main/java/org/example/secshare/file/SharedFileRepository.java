package org.example.secshare.file;

import org.example.secshare.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SharedFileRepository extends JpaRepository<SharedFile, UUID> {

    List<SharedFile> findByOwnerAndDeletedFalseOrderByCreatedAtDesc(User owner);

    Optional<SharedFile> findByIdAndDeletedFalse(UUID id);
}

