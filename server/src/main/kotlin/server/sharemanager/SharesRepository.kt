package server.sharemanager

import org.springframework.data.jpa.repository.JpaRepository

interface SharesRepository : JpaRepository<Shares, Long> {
    fun findByUserId(userId: Long): Shares?
}