package org.e2ee.data.remote.websocket

import kotlinx.serialization.Serializable

@Serializable
data class ChatRequest(
    val messageId: String,
    val senderId: String,
    val receiverId: String,
    val messageType: MessageType,
    val encodedMessage: String,
    val createdAt: String
)

@Serializable
data class ChatMessage(
    val messageId: String,
    val senderId: String,
    val receiverId: String,
    val messageType: MessageType,
    val encodedMessage: String,
    val createdAt: String? = null
)

@Serializable
data class MessageAck(
    val messageId: String,
    val status: MessageStatus,
    val reason: String? = null
)

@Serializable
data class DeliveryReceiptRequest(
    val messageId: String,
    val senderId: String,
    val receiverId: String
)

@Serializable
enum class MessageType {
    PRE_KEY_MESSAGE,
    RATCHET_MESSAGE
}

@Serializable
enum class MessageStatus {
    SENT,
    DELIVERED,
    EXPIRED,
    FAILED
}