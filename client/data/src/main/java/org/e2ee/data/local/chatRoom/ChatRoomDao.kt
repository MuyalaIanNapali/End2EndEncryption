package org.e2ee.data.local.chatRoom

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ChatRoomDao {

    @Insert
    suspend fun insertChatRoom(chatRoom: ChatRoom)

    @Query("""
        UPDATE chat_room
        SET lastMessage = :lastMessage, lastMessageTimestamp = :lastMessageTime
        WHERE sessionId = :sessionId
    """)
    suspend fun updateLastMessage(sessionId: String, lastMessage: String, lastMessageTime: Long)

    @Query("DELETE FROM chat_room WHERE sessionId = :sessionId")
    suspend fun deleteChatRoomBySessionId(sessionId: String)

    @Query("SELECT * FROM chat_room WHERE sessionId = :sessionId LIMIT 1")
    suspend fun getChatRoomBySessionId(sessionId: String): ChatRoom?

    @Query("SELECT * FROM chat_room")
    fun getAllChatRooms(): Flow<List<ChatRoom>>

    @Query("SELECT * FROM chat_room WHERE recipientId = :otherUserId LIMIT 1")
    suspend fun getChatRoomByRecipientId(otherUserId: Long): ChatRoom?

    @Query("SELECT * FROM chat_room")
    fun getAllChatRoomsForBackup(): List<ChatRoom>
}