package org.e2ee.domain.model

data class ChatRoomDomain(
    val sessionId: String,
    val senderId: Long,
    val receiverId: Long,
    val lastMessage: String?,
    val lastMessageTimestamp: Long?
)
