package org.e2ee.client.models

import kotlinx.datetime.LocalDateTime
import org.e2ee.domain.model.Message
import org.e2ee.domain.model.MessageStatus

data class ChatMessageUi(
    val id: String,
    val sessionId: String?,
    val text: String,
    val timestamp: String,
    val status: MessageStatus = MessageStatus.SENDING,
    val isSentByUser: Boolean
)

fun Message.toChatMessageUi(): ChatMessageUi {
    return ChatMessageUi(
        id = remoteId,
        sessionId = sessionId,
        text = content,
        timestamp = sentTime.toHourMinute(),
        status = status,
        isSentByUser = isSentByUser
    )
}

fun LocalDateTime.toHourMinute(): String {
    return "${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}"
}