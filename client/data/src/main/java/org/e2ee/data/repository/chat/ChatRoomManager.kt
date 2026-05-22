package org.e2ee.data.repository.chat

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

        val remoteUserResult = remoteUserRepository.getUserByUserId(
            otherUserId.toLong()
        )

        if (remoteUserResult !is ApiResult.Success) {
            throw IllegalStateException(
                "Failed to fetch remote user for chat room: $otherUserId"
            )
        }

        val newChatRoom = ChatRoom(
            sessionId = sessionId,
            senderId = localUser.userId,
            recipientId = otherUserId.toLong()
        )

        chatRoomRepository.insertChatRoom(newChatRoom)

        return chatRoomRepository.getChatRoomBySessionId(sessionId)
            ?: throw IllegalStateException(
                "Chat room was inserted but could not be fetched: $sessionId"
            )
    }

    suspend fun insertChatRoomIfMissing(
        sessionId: String,
        senderId: Long,
        recipientId: Long
    ) {
        val existingRoom = chatRoomRepository.getChatRoomBySessionId(sessionId)

        if (existingRoom != null) {
            return
        }

        chatRoomRepository.insertChatRoom(
            ChatRoom(
                sessionId = sessionId,
                senderId = senderId,
                recipientId = recipientId
            )
        )
    }
}