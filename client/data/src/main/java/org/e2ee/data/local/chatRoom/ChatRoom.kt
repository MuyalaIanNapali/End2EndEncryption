package org.e2ee.data.local.chatRoom

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable
import org.e2ee.data.local.friends.Friends
import org.e2ee.data.local.user.User

@Serializable
@Entity(
    tableName = "chat_room",
    foreignKeys = [
        ForeignKey(
            entity = User::class,
            parentColumns = ["userId"],
            childColumns = ["senderId"],
            onDelete = ForeignKey.CASCADE
        ),
        ForeignKey(
            entity = Friends::class,
            parentColumns = ["userId"],
            childColumns = ["recipientId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        androidx.room.Index(value = ["senderId"]),
        androidx.room.Index(value = ["recipientId"])
    ]
)
data class ChatRoom (
    @PrimaryKey
    val sessionId: String,

    val senderId: Long,

    val recipientId: Long,

    val lastMessage: String? = null,

    val lastMessageTimestamp: Long? = null

)