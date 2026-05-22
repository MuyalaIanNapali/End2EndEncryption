package org.e2ee.data.repository.chat

import org.e2ee.data.local.messages.MessageStatus
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.remote.websocket.ChatMessage
import org.e2ee.data.remote.websocket.ChatStompClient
import org.e2ee.data.remote.websocket.DeliveryReceiptRequest
import java.time.LocalDateTime
import java.time.ZoneId
import javax.inject.Inject

class ChatMessageReceiver @Inject constructor(
    private val userRepository: LocalUserRepository,
    private val messagesRepository: MessagesRepository,
    private val chatRoomManager: ChatRoomManager,
    private val chatCryptoManager: ChatCryptoManager,
    private val sessionIdFactory: ChatSessionIdFactory,
    private val messageNotifier: MessageNotifier
) {

    suspend fun receiveIncomingMessage(
        encryptedMessage: ChatMessage,
        stompClient: ChatStompClient
    ) {
        try {
            val localUser = userRepository.getUser()
                ?: throw IllegalStateException(
                    "No local user found for incoming message decryption"
                )

            val receiverId = encryptedMessage.receiverId
            val senderId = encryptedMessage.senderId

            if (localUser.userId != receiverId.toLong()) {
                println(
                    "Received message intended for user $receiverId, but local user is ${localUser.userId}"
                )
                return
            }

            val sessionId = sessionIdFactory.createSessionId(
                localUserId = receiverId,
                otherUserId = senderId
            )

            val decryptedBody = chatCryptoManager.decryptIncomingMessage(
                encryptedMessage = encryptedMessage,
                sessionId = sessionId,
                localUserId = localUser.userId
            )

            val chatRoom = chatRoomManager.createOrFetchChatRoom(
                sessionId = sessionId,
                localUser = localUser,
                otherUserId = senderId
            )

            val localMessage = Messages(
                remoteMessageId = encryptedMessage.messageId,
                sessionId = chatRoom.sessionId,
                content = decryptedBody,
                timestamp = encryptedMessage.createdAt.toEpochMillisOrNow(),
                status = MessageStatus.RECEIVED,
                isSentByUser = false
            )

            messagesRepository.insertMessage(localMessage)

            stompClient.sendDeliveredReceipt(
                DeliveryReceiptRequest(
                    messageId = encryptedMessage.messageId,
                    senderId = encryptedMessage.senderId,
                    receiverId = encryptedMessage.receiverId
                )
            )

            messageNotifier.showMessageNotification(
                senderId = encryptedMessage.senderId,
                message = decryptedBody
            )
        } catch (e: Exception) {
            println("Error processing incoming message: ${e.message}")
        }
    }

    private fun String?.toEpochMillisOrNow(): Long {
        return this
            ?.let { LocalDateTime.parse(it) }
            ?.atZone(ZoneId.systemDefault())
            ?.toInstant()
            ?.toEpochMilli()
            ?: System.currentTimeMillis()
    }
}