package server.chat

import tools.jackson.databind.ObjectMapper
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import server.users.UserRepository
import java.time.LocalDateTime
import java.util.UUID

@Service
class ChatService(
    private val userRepository: UserRepository,
    private val pendingMessageRepository: PendingMessageRepository,
    private val objectMapper: ObjectMapper
) {

    fun validateUsers(senderId: Long, receiverId: Long) {
        if (!userRepository.existsById(senderId)) {
            throw IllegalArgumentException("Sender not found")
        }

        if (!userRepository.existsById(receiverId)) {
            throw IllegalArgumentException("Receiver not found")
        }
    }

    @Transactional
    fun createPendingMessage(request: ChatRequest): ChatMessage {
        validateUsers(
            request.senderId.toLong(),
            request.receiverId.toLong()
        )


        val chatMessage = ChatMessage(
            messageId = request.messageId,
            senderId = request.senderId,
            receiverId = request.receiverId,
            messageType = request.messageType,
            message = request.encodedMessage,
            createdAt = request.createdAt
        )

        val pendingMessage = PendingMessage(
            id = request.messageId,
            senderId = request.senderId,
            receiverId = request.receiverId,
            payload= chatMessage,
            status = MessageStatus.SENT,
            createdAt = LocalDateTime.now(),
        )

        pendingMessageRepository.save(pendingMessage)

        return chatMessage
    }

    @Transactional
    fun markDelivered(messageId: String) {
        val message = pendingMessageRepository.findById(messageId)
            .orElseThrow { IllegalArgumentException("Message not found") }

        message.status = MessageStatus.DELIVERED
        message.deliveredAt = LocalDateTime.now()

        pendingMessageRepository.save(message)
    }

    fun getPendingMessagesFor(receiverId: String): List<ChatMessage> {
        return pendingMessageRepository
            .findByReceiverIdAndStatus(receiverId, MessageStatus.SENT)
            .map { it.payload }
    }
}