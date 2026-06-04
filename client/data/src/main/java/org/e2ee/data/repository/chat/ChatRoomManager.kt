package org.e2ee.data.repository.chat

import android.util.Log
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.e2ee.data.local.chatRoom.ChatRoom
import org.e2ee.data.local.chatRoom.ChatRoomRepository
import org.e2ee.data.local.user.User
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import javax.inject.Inject

class ChatRoomManager @Inject constructor(
    private val chatRoomRepository: ChatRoomRepository,
    private val remoteUserRepository: RemoteUserRepository
) {

    suspend fun createOrFetchChatRoom(
        sessionId: String,
        localUser: User,
        otherUserId: String
    ): ChatRoom {
        val existingRoom = chatRoomRepository.getChatRoomBySessionId(sessionId)

        if (existingRoom != null) {
            return existingRoom
        }
        Log.d("ChatRoomManager", "No existing chat room for sessionId: $sessionId, creating new one with otherUserId: $otherUserId")

        val remoteUserResult = remoteUserRepository.getUserByUserId(
            otherUserId.toLong()
        )

        if (remoteUserResult !is ApiResult.Success) {
            throw IllegalStateException(
                "Failed to fetch remote user for chat room: $otherUserId"
            )
        }
        Log.d("ChatRoomManager", "Fetched remote user for chat room: ${remoteUserResult.data}")

        val newChatRoom = ChatRoom(
            sessionId = sessionId,
            senderId = localUser.userId,
            recipientId = otherUserId.toLong()
        )
        Log.d("ChatRoomManager", "Inserting new chat room into repository: $newChatRoom")

        chatRoomRepository.insertChatRoom(newChatRoom)
        Log.d("ChatRoomManager", "Inserted new chat room, fetching it back to confirm: sessionId: $sessionId")

        return chatRoomRepository.getChatRoomBySessionId(sessionId)
            ?: throw IllegalStateException(
                "Chat room was inserted but could not be fetched: $sessionId"
            )
    }

    fun getAllChatRoomsForUser(): Flow<List<ChatRoom>> {
        return chatRoomRepository.getAllChatRooms()
    }

    suspend fun getChatRoomByOtherUserId(otherUserId: String): ChatRoom? {
        return chatRoomRepository.getChatRoomByRecipientId(otherUserId)
    }

    suspend fun updateLastMessage(sessionId: String, lastMessage: String, lastMessageTime: Long) {
        chatRoomRepository.updateLastMessage(sessionId, lastMessage, lastMessageTime)
    }
}