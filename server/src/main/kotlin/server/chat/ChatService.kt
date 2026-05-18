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

        val messageId = UUID.randomUUID().toString()

        val chatMessage = ChatMessage(
            messageId = messageId,
            senderId = request.senderId,
            receiverId = request.receiverId,
            message = request.message
        )

        val payloadJson = objectMapper.writeValueAsString(chatMessage)

        val pendingMessage = PendingMessage(
            id = messageId,
            senderId = request.senderId,
            receiverId = request.receiverId,
            payloadJson = payloadJson,
            status = MessageStatus.SENT,
            createdAt = LocalDateTime.now()
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
            .map { objectMapper.readValue(it.payloadJson, ChatMessage::class.java) }
    }
}