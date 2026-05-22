package org.e2ee.data.repository.chat

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.repository.mapper.toMessage
import javax.inject.Inject
import org.e2ee.domain.repository.ChatRepository as ChatRepositoryInterface
import org.e2ee.domain.model.Message

class ChatRepository @Inject constructor(
    private val chatConnectionManager: ChatConnectionManager,
    private val chatMessageSender: ChatMessageSender,
    private val chatMessageObserver: ChatMessageObserver
): ChatRepositoryInterface {

    override suspend fun observeMessages(
        sessionId: String
    ): Flow<List<Message>> {
        return chatMessageObserver
            .observeMessages(sessionId)
            .map { messages ->
                messages.map { it.toMessage() }
            }
    }

    override fun connect() {
        chatConnectionManager.connect()
    }

    override suspend fun sendMessage(
        receiverId: String,
        content: String
    ) {
        chatConnectionManager.sendMessage(
            receiverId = receiverId,
            content = content,
            sender = chatMessageSender
        )
    }

    override fun disconnect() {
        chatConnectionManager.disconnect()
    }
}