package server.chat

import server.message.Message
import java.time.LocalDateTime

data class ChatRequest(
    val senderId: String,
    val receiverId: String,
    val message: Message
)

data class ChatMessage(
    val messageId: String,
    val senderId: String,
    val receiverId: String,
    val message: Message,
    val createdAt: LocalDateTime = LocalDateTime.now()
)

data class MessageAck(
    val messageId: String,
    val status: MessageStatus,
    val reason: String? = null
)

enum class MessageStatus {
    SENT,
    DELIVERED,
    EXPIRED,
    FAILED
}

data class DeliveryReceiptRequest(
    val messageId: String,
    val senderId: String,
    val receiverId: String
)