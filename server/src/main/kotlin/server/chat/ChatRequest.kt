package server.chat


data class ChatRequest(
    val messageId: String,
    val senderId: String,
    val receiverId: String,
    val messageType: MessageType,
    val encodedMessage: String,
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
    val message: String,
    val createdAt: String
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