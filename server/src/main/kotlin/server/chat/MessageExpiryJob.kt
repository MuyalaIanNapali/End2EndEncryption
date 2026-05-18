package server.chat

import org.springframework.messaging.simp.SimpMessagingTemplate
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime

@Component
class MessageExpiryJob(
    private val pendingMessageRepository: PendingMessageRepository,
    private val messagingTemplate: SimpMessagingTemplate
) {

    @Scheduled(fixedRate = 60_000)
    @Transactional
    fun expireOldMessages() {
        val cutoff = LocalDateTime.now().minusDays(7)

        val expiredMessages = pendingMessageRepository.findByStatusAndCreatedAtBefore(
            MessageStatus.SENT,
            cutoff
        )

        expiredMessages.forEach { message ->
            message.status = MessageStatus.EXPIRED
            pendingMessageRepository.save(message)

            messagingTemplate.convertAndSendToUser(
                message.senderId,
                "/queue/message-status",
                MessageAck(
                    messageId = message.id,
                    status = MessageStatus.EXPIRED,
                    reason = "Message was not delivered within 7 days"
                )
            )
        }
    }
}