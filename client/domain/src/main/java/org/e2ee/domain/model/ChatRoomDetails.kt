package org.e2ee.domain.model

data class ChatRoomDetails(
    val sessionId: String,
    val otherUserId: Long,
    val otherUsername: String,
    val otherUserEmail: String,
    val unreadMessageCount: Int,
    val lastMessage: String,
    val lastMessageTimestamp: Long?
)
