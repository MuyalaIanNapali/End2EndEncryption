package org.e2ee.data.repository.chat

import kotlinx.coroutines.flow.Flow
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesRepository
import javax.inject.Inject

class ChatMessageObserver @Inject constructor(
    private val messagesRepository: MessagesRepository
) {

    fun observeMessages(
        sessionId: String
    ): Flow<List<Messages>> {
        return messagesRepository.observeMessagesBySessionId(sessionId)
    }
}