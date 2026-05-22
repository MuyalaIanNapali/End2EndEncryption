package org.e2ee.data.repository.chat

import kotlinx.coroutines.flow.Flow
import org.e2ee.data.local.messages.Messages
import javax.inject.Inject

class ChatRepository @Inject constructor(
    private val chatConnectionManager: ChatConnectionManager,
    private val chatMessageSender: ChatMessageSender,
    private val chatMessageObserver: ChatMessageObserver
) {

    fun observeMessages(
        sessionId: String
    ): Flow<List<Messages>> {
        return chatMessageObserver.observeMessages(sessionId)
    }

    fun connect() {
        chatConnectionManager.connect()
    }

    suspend fun sendMessage(
        receiverId: String,
        content: String
    ) {
        chatConnectionManager.sendMessage(
            receiverId = receiverId,
            content = content,
            sender = chatMessageSender
        )
    }

    fun disconnect() {
        chatConnectionManager.disconnect()
    }
}