package org.e2ee.client.models

data class ChatPreviewCard(
    val sessionId: String,
    val contactId: Long,
    val contactName: String,
    val contactEmail: String,
    val lastMessage: String,
    val timestamp: String,
    val unreadMessageCount: Int = 0
)