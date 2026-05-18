package server.chat

import org.springframework.data.jpa.repository.JpaRepository
import java.time.LocalDateTime

interface PendingMessageRepository : JpaRepository<PendingMessage, String> {

    fun findByReceiverIdAndStatus(
        receiverId: String,
        status: MessageStatus
    ): List<PendingMessage>

    fun findByStatusAndCreatedAtBefore(
        status: MessageStatus,
        createdAt: LocalDateTime
    ): List<PendingMessage>
}