package org.e2ee.data.repository.chat

import android.util.Log
import org.e2ee.data.local.friends.Friends
import org.e2ee.data.local.friends.FriendsRepository
import org.e2ee.data.local.messages.MessageStatus
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.websocket.ChatMessage
import org.e2ee.data.remote.websocket.ChatStompClient
import org.e2ee.data.remote.websocket.DeliveryReceiptRequest
import org.e2ee.domain.notifications.MessageNotifier
import java.time.LocalDateTime
import java.time.ZoneId
import javax.inject.Inject

class ChatMessageReceiver @Inject constructor(
    private val userRepository: LocalUserRepository,
    private val messagesRepository: MessagesRepository,
    private val chatRoomManager: ChatRoomManager,
    private val chatCryptoManager: ChatCryptoManager,
    private val sessionIdFactory: ChatSessionIdFactory,
    private val messageNotifier: MessageNotifier,
    private val friendsRepository: FriendsRepository,
    private val remoteUserRepository: RemoteUserRepository
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
            Log.d("ChatMessageReceiver", "Received message: $encryptedMessage for local user ${localUser.userId}")

            //check if sender is in friends
            val friend = friendsRepository.getFriendById(encryptedMessage.senderId.toLong())
            if (friend == null) {
                val user = remoteUserRepository.getUserByUserId(encryptedMessage.senderId.toLong())
                if (user is org.e2ee.data.remote.network.ApiResult.Success) {
                    val userDetails = user.data
                    friendsRepository.addFriend(
                        Friends(
                            userId = userDetails.id,
                            username = userDetails.username,
                            email = userDetails.email,
                            avatarUrl = userDetails.avatarUrl
                        )
                    )
                } else {
                    println("Sender with id ${encryptedMessage.senderId} is not a friend and could not be fetched from remote repository. Message will be ignored.")
                    return
                }
            }

            val receiverId = encryptedMessage.receiverId
            val senderId = encryptedMessage.senderId

            Log.d("ChatMessageReceiver", "Message receiverId: $receiverId, senderId: $senderId, localUserId: ${localUser.userId}")

            if (localUser.userId != receiverId.toLong()) {
                println(
                    "Received message intended for user $receiverId, but local user is ${localUser.userId}"
                )
                return
            }

            Log.d("ChatMessageReceiver", "Processing message for local user ${localUser.userId}")

            val sessionId = sessionIdFactory.createSessionId(
                localUserId = receiverId,
                otherUserId = senderId
            )
            Log.d("ChatMessageReceiver", "Derived sessionId: $sessionId for message from senderId: $senderId")

            val decryptedBody = chatCryptoManager.decryptIncomingMessage(
                encryptedMessage = encryptedMessage,
                sessionId = sessionId,
                localUserId = localUser.userId
            )
            Log.d("ChatMessageReceiver", "Decrypted message body: $decryptedBody")
            val chatRoom = chatRoomManager.createOrFetchChatRoom(
                sessionId = sessionId,
                localUser = localUser,
                otherUserId = senderId
            )
            Log.d("ChatMessageReceiver", "Fetched or created chat room with sessionId: ${chatRoom.sessionId} for senderId: $senderId")

            val localMessage = Messages(
                remoteMessageId = encryptedMessage.messageId,
                sessionId = chatRoom.sessionId,
                content = decryptedBody,
                timestamp = encryptedMessage.createdAt.toEpochMillisOrNow(),
                status = MessageStatus.RECEIVED,
                isSentByUser = false
            )

            messagesRepository.insertMessage(localMessage)
            Log.d("ChatMessageReceiver", "Inserted message into local database with id: $localMessage")

            stompClient.sendDeliveredReceipt(
                DeliveryReceiptRequest(
                    messageId = encryptedMessage.messageId,
                    senderId = encryptedMessage.senderId,
                    receiverId = encryptedMessage.receiverId
                )
            )
            Log.d("ChatMessageReceiver", "Sent delivery receipt for messageId: ${encryptedMessage.messageId}")

            chatRoomManager.updateLastMessage(
                sessionId = chatRoom.sessionId,
                lastMessage = decryptedBody,
                lastMessageTime = localMessage.timestamp
            )

            messageNotifier.showMessageNotification(
                senderId = encryptedMessage.senderId,
                messageBody = decryptedBody
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