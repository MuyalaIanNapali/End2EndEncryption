package server.keymanager

import org.springframework.data.jpa.repository.JpaRepository

interface OpkNotificationRepository: JpaRepository<OpkNotificationState, Long> {
    fun findByUserId(userId: Long): OpkNotificationState?
}