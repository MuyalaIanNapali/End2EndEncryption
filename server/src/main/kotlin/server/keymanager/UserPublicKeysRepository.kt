package server.keymanager

import org.springframework.data.jpa.repository.JpaRepository

interface UserPublicKeysRepository: JpaRepository<UserPublicKeys, Long> {
    fun findByUserId(userId: Long): UserPublicKeys?
}