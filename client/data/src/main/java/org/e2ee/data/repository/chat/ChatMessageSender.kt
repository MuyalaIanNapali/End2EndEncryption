package org.e2ee.data.repository.chat

import org.e2ee.common.PreKeyMessage
import org.e2ee.common.RatchetMessage
import org.e2ee.data.local.messages.MessageStatus
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.remote.websocket.ChatRequest
import org.e2ee.data.remote.websocket.ChatStompClient
import org.e2ee.data.remote.websocket.MessageType
import java.time.LocalDateTime
import java.util.UUID
import javax.inject.Inject

class ChatMessageSender @Inject constructor(
    private val userRepository: LocalUserRepository,
    private val messagesRepository: MessagesRepository,
    private val chatRoomManager: ChatRoomManager,
    private val chatCryptoManager: ChatCryptoManager,
    private val sessionIdFactory: ChatSessionIdFactory
) {

    suspend fun sendMessage(
        receiverId: String,
        content: String,
        stompClient: ChatStompClient
    ) {
        val localUser = userRepository.getUser()
            ?: throw IllegalStateException("No local user found")

        val senderId = localUser.userId.toString()
        val messageId = UUID.randomUUID().toString()

        val sessionId = sessionIdFactory.createSessionId(
            localUserId = senderId,
            otherUserId = receiverId
        )

        val encryptedOutgoingMessage = chatCryptoManager.encryptOutgoingMessage(
            sessionId = sessionId,
            senderId = senderId,
            receiverId = receiverId,
            content = content
        )

        val chatRoom = chatRoomManager.createOrFetchChatRoom(
            sessionId = sessionId,
            localUser = localUser,
            otherUserId = receiverId
        )

        messagesRepository.insertMessage(
            Messages(
                localId = 0L,
                remoteMessageId = messageId,
                sessionId = chatRoom.sessionId,
                content = content,
                timestamp = System.currentTimeMillis(),
                status = MessageStatus.SENDING,
                isSentByUser = true
            )
        )

        val messageType = when (encryptedOutgoingMessage) {
            is PreKeyMessage -> MessageType.PRE_KEY_MESSAGE
            is RatchetMessage -> MessageType.RATCHET_MESSAGE
            else -> throw IllegalStateException("Unsupported message type")
        }

        stompClient.sendChatMessage(
            ChatRequest(
                messageId = messageId,
                senderId = senderId,
                receiverId = receiverId,
                messageType = messageType,
                message = encryptedOutgoingMessage,
                createdAt = LocalDateTime.now().toString()
            )
        )
    }
}