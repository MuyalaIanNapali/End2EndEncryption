package org.e2ee.data.repository.backup

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.e2ee.data.local.chatRoom.ChatRoomRepository
import org.e2ee.data.local.database.DatabaseBackupPayload
import org.e2ee.data.local.database.deserializeBackup
import org.e2ee.data.local.friends.FriendsRepository
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.local.user.LocalUserRepository
import javax.inject.Inject

class BackupExporter @Inject constructor(
    private val userRepository: LocalUserRepository,
    private val friendsRepository: FriendsRepository,
    private val chatRoomRepository: ChatRoomRepository,
    private val messagesRepository: MessagesRepository

) {

    suspend fun export(): DatabaseBackupPayload = withContext(Dispatchers.IO) {
        DatabaseBackupPayload(
            userRepository.getUser(),
            friendsRepository.getAllFriends(),
            chatRoomRepository.getAllChatRoomsForBackup(),
            messagesRepository.getAllMessages()
        )
    }

    suspend fun import(backupBytes: ByteArray) = withContext(Dispatchers.IO) {
        val payload = deserializeBackup(backupBytes)
        userRepository.insertUser(payload.users!!)
        friendsRepository.addFriends(payload.friends)
        chatRoomRepository.insertChatRooms(payload.chatRooms)
        messagesRepository.insertMessages(payload.messages)
    }


}