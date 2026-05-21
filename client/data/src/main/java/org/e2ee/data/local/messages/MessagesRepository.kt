package org.e2ee.data.local.messages

import androidx.annotation.WorkerThread
import kotlinx.coroutines.flow.Flow

class MessagesRepository(
    private val dao: MessagesDao
) {
    @WorkerThread
    suspend fun insertMessage(message: Messages) {
        dao.insertMessage(message)
    }

    fun observeMessagesBySessionId(sessionId: String): Flow<List<Messages>> {
        return dao.observeMessagesBySessionId(sessionId)
    }

    @WorkerThread
    suspend fun getMessagesBySessionId(sessionId: String): List<Messages> {
        return dao.getMessagesBySessionId(sessionId)
    }

    @WorkerThread
    suspend fun deleteMessagesBySessionId(sessionId: String) {
        dao.deleteMessagesBySessionId(sessionId)
    }

    @WorkerThread
    suspend fun updateStatus(remoteMessageId: String, status: MessageStatus) {
        dao.updateStatus(remoteMessageId, status)
    }
}