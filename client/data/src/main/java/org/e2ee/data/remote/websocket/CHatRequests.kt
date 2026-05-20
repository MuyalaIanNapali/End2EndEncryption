package org.e2ee.data.remote.websocket

import org.e2ee.common.Message
import java.time.LocalDateTime

data class ChatRequest(
    val messageId: String,
    val senderId: String,
    val receiverId: String,
    val messageType: MessageType,
    val message: Message,
    val createdAt: String
)

enum class MessageType {
    PRE_KEY_MESSAGE,
    RATCHET_MESSAGE
}

data class ChatMessage(
    val messageId: String,
    val senderId: String,
    val receiverId: String,
    val messageType: MessageType,
    val message: Message,
    val createdAt: String? = null
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