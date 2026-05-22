package org.e2ee.data.repository.chat

import org.e2ee.data.local.messages.MessageStatus
import org.e2ee.data.local.messages.MessagesRepository
import javax.inject.Inject
import org.e2ee.data.remote.websocket.MessageStatus as RemoteMessageStatus

class ChatMessageStatusUpdater @Inject constructor(
    private val messagesRepository: MessagesRepository
) {

    suspend fun updateStatus(
        messageId: String,
        status: RemoteMessageStatus
    ) {
        val localStatus = when (status) {
            RemoteMessageStatus.SENT -> MessageStatus.SENT
            RemoteMessageStatus.DELIVERED -> MessageStatus.DELIVERED
            RemoteMessageStatus.FAILED -> MessageStatus.FAILED
            else -> return
        }

        messagesRepository.updateStatus(
            remoteMessageId = messageId,
            status = localStatus
        )
    }
}