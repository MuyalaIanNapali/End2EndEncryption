package org.e2ee.domain.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import org.e2ee.domain.model.ChatRoomDomain
import org.e2ee.domain.model.ConnectionState
import org.e2ee.domain.model.Message

interface ChatRepository {

    val connectionState: StateFlow<ConnectionState>
    fun connect()

    fun disconnect()

    suspend fun sendMessage(
        receiverId: String,
        username: String,
        content: String
    ): String

    fun observeMessages(
        sessionId: String
    ): Flow<List<Message>>

    fun getChatRooms(): Flow<List<ChatRoomDomain>>

    suspend fun getUnreadMessageCount(sessionId: String): Int

    suspend fun getChatRoomByReceiverId(receiverId: String): ChatRoomDomain?

    suspend fun updateLastMessage(sessionId: String, lastMessage: String, lastMessageTime: Long)

    suspend fun markMessagesAsRead(sessionId: String)
}