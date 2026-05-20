package org.e2ee.data.local.messages

import androidx.room.Entity
import androidx.room.ForeignKey
import org.e2ee.data.local.chatRoom.ChatRoom

@Entity(
    tableName = "messages",
    primaryKeys = ["messageId"],
    foreignKeys = [
        ForeignKey(
            entity = ChatRoom::class,
            parentColumns = ["sessionId"],
            childColumns = ["sessionId"],
            onDelete = ForeignKey.CASCADE
        )
    ]
)
data class Messages(
    val messageId: String,
    val sessionId: ChatRoom,
    val content: String,
    val timestamp: Long,
    val status: MessageStatus,
    val isSentByUser: Boolean
)

enum class MessageStatus {
    SENT,
    DELIVERED,
    EXPIRED,
    FAILED,
    RECEIVED
}
