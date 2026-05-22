package org.e2ee.domain.model

import java.time.LocalDateTime

data class Message(
    val remoteId: String,
    val sessionId: String,
    val content: String,
    val sentTime: kotlinx.datetime.LocalDateTime,
    val status: MessageStatus,
    val isSentByUser: Boolean
)
