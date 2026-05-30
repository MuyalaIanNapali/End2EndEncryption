package org.e2ee.data.local.chatRoom

import androidx.annotation.WorkerThread
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class ChatRoomRepository @Inject constructor(
    private val dao: ChatRoomDao
) {

    @WorkerThread
    suspend fun insertChatRoom(chatRoom: ChatRoom) {
        dao.insertChatRoom(chatRoom)
    }

    @WorkerThread
    suspend fun updateLastMessage(sessionId: String, lastMessage: String, lastMessageTime: Long) {
        dao.updateLastMessage(sessionId, lastMessage, lastMessageTime)
    }

    @WorkerThread
    suspend fun deleteChatRoomBySessionId(sessionId: String) {
        dao.deleteChatRoomBySessionId(sessionId)
    }

    @WorkerThread
    suspend fun getChatRoomBySessionId(sessionId: String): ChatRoom? {
        return dao.getChatRoomBySessionId(sessionId)
    }

    @WorkerThread
    fun getAllChatRooms(): Flow<List<ChatRoom>> {
        return dao.getAllChatRooms()
    }


}