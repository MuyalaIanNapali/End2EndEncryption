package org.e2ee.client.models

data class ChatPreviewCard(
    val sessionId: String,
    val contactName: String,
    val lastMessage: String,
    val timestamp: String,
    val unreadMessageCount: Int = 0
)