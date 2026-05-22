package org.e2ee.data.repository.mapper

import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import org.e2ee.data.local.messages.MessageStatus
import org.e2ee.data.local.messages.Messages
import org.e2ee.domain.model.Message
import kotlin.time.Instant

fun Messages.toMessage(): Message {
    val time = Instant.fromEpochMilliseconds(this.timestamp)

    return Message(
        remoteId = this.remoteMessageId,
        sessionId = this.sessionId,
        content = this.content,
        sentTime = time.toLocalDateTime(TimeZone.currentSystemDefault()),
        status = this.status.toMessageStatus(),
        isSentByUser = this.isSentByUser
    )
}


fun MessageStatus.toMessageStatus(): org.e2ee.domain.model.MessageStatus {
    return when(this) {
        MessageStatus.SENT -> org.e2ee.domain.model.MessageStatus.SENT
        MessageStatus.DELIVERED -> org.e2ee.domain.model.MessageStatus.DELIVERED
        MessageStatus.FAILED -> org.e2ee.domain.model.MessageStatus.FAILED
        MessageStatus.SENDING -> org.e2ee.domain.model.MessageStatus.SENDING
        else -> {
            org.e2ee.domain.model.MessageStatus.FAILED
        }
    }
}