package org.e2ee.domain.usecase

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.e2ee.domain.model.ChatRoomDetails
import org.e2ee.domain.repository.ChatRepository
import org.e2ee.domain.repository.UserRepository
import javax.inject.Inject

class LoadChatRoomsUseCase @Inject constructor(
    private val chatRepository: ChatRepository,
    private val userRepository: UserRepository
) {
    operator fun invoke(): Flow<List<ChatRoomDetails>> {
        return chatRepository.getChatRooms().map { rooms ->
            rooms.map { room ->
                val contact = userRepository.getContactById(room.receiverId)
                val unreadCount = chatRepository.getUnreadMessageCount(room.sessionId)

                ChatRoomDetails(
                    sessionId = room.sessionId,
                    otherUserId = room.receiverId,
                    otherUsername = contact?.username ?: "Unknown",
                    lastMessage = room.lastMessage ?: "",
                    unreadMessageCount = unreadCount,
                    lastMessageTimestamp = room.lastMessageTimestamp
                )
            }
        }
    }
}