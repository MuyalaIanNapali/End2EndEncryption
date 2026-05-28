package org.e2ee.client.models

data class ChatMessageUi(
    val id: String,
    val sessionId: String?,
    val text: String,
    val timestamp: String,
    val isSentByUser: Boolean
)