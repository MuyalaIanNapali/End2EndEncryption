package org.e2ee.data.local.messages

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface MessagesDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: Messages)

    @Query("""
        SELECT * FROM messages 
        WHERE sessionId = :sessionId 
        ORDER BY timestamp ASC
    """)
    fun observeMessagesBySessionId(sessionId: String): Flow<List<Messages>>

    @Query("""
        SELECT * FROM messages 
        WHERE sessionId = :sessionId 
        ORDER BY timestamp ASC
    """)
    suspend fun getMessagesBySessionId(sessionId: String): List<Messages>

    @Query("DELETE FROM messages WHERE sessionId = :sessionId")
    suspend fun deleteMessagesBySessionId(sessionId: String)

    @Query("""
        UPDATE messages
        SET status = :status
        WHERE remoteMessageId = :remoteMessageId
    """)
    suspend fun updateStatus(
        remoteMessageId: String,
        status: MessageStatus
    )
}