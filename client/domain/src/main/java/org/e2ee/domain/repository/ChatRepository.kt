package org.e2ee.domain.repository

import kotlinx.coroutines.flow.Flow
import org.e2ee.domain.model.Message

interface ChatRepository {
    fun connect()

    fun disconnect()

    suspend fun sendMessage(
        receiverId: String,
        content: String
    )

    suspend fun observeMessages(
        sessionId: String
    ): Flow<List<Message>>
}