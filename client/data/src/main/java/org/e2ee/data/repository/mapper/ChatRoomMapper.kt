package org.e2ee.data.repository.mapper

import org.e2ee.data.local.chatRoom.ChatRoom
import org.e2ee.domain.model.ChatRoomDomain

fun ChatRoom.toDomain(): ChatRoomDomain {
    return ChatRoomDomain(
        sessionId = sessionId,
        senderId = senderId,
        receiverId = recipientId,
        lastMessage = lastMessage,
        lastMessageTimestamp = lastMessageTimestamp
    )
}