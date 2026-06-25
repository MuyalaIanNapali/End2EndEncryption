package org.e2ee.data.repository.backup

import org.e2ee.data.local.chatRoom.ChatRoomRepository
import org.e2ee.data.local.database.DatabaseBackupPayload
import org.e2ee.data.local.friends.FriendsRepository
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.local.user.LocalUserRepository
import javax.inject.Inject

class BackupExporter @Inject constructor(
    private val userRepository: LocalUserRepository,
    private val friendsRepository: FriendsRepository,
    private val chatRoomRepository: ChatRoomRepository,
    private val messagesRepository: MessagesRepository

) {

    suspend fun export(): DatabaseBackupPayload {

        return DatabaseBackupPayload(
            userRepository.getUser(),
            friendsRepository.getAllFriends(),
            chatRoomRepository.getAllChatRoomsForBackup(),
            messagesRepository.getAllMessages() as List<Messages>
        )
    }
}