package org.e2ee.data.local.database

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.e2ee.data.local.chatRoom.ChatRoom
import org.e2ee.data.local.friends.Friends
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.user.User

@Serializable
data class DatabaseBackupPayload(
    val users: User?,
    val friends: List<Friends>,
    val chatRooms: List<ChatRoom>,
    val messages: List<Messages>,
)

fun serializeBackup(payload: DatabaseBackupPayload): ByteArray {
    val json = Json.encodeToString(payload)
    return json.toByteArray(Charsets.UTF_8)
}

fun deserializeBackup(data: ByteArray): DatabaseBackupPayload {
    val json = data.toString(Charsets.UTF_8)
    return Json.decodeFromString(json)
}
