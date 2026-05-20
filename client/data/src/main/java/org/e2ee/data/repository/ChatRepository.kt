package org.e2ee.data.repository

import org.e2ee.crypto.Crypto
import org.e2ee.common.PreKeyMessage as CryptoPreKeyMessage
import org.e2ee.data.local.chatRoom.ChatRoom
import org.e2ee.data.local.friends.Friends
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesDao
import org.e2ee.data.local.user.User
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.ratchetStates.RatchetStatesRepository
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.user.LocalUserRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.common.RatchetMessage
import org.e2ee.common.UserKeysDto
import org.e2ee.crypto.entities.DecryptMessageDto
import org.e2ee.data.local.chatRoom.ChatRoomRepository
import org.e2ee.data.local.messages.MessageStatus
import org.e2ee.data.local.ratchetStates.toRatchetStateDto
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.websocket.ChatMessage
import org.e2ee.data.remote.websocket.ChatRequest
import org.e2ee.data.remote.websocket.ChatStompClient
import org.e2ee.data.remote.websocket.DeliveryReceiptRequest

class ChatRepository(
    private val accessToken: String,
    private val messagesDao: MessagesDao,
    private val crypto : Crypto,
    private val userRepository: LocalUserRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val remoteUserRepository: RemoteUserRepository,
    private val opkRepository : OneTimePreKeysRepository,
    private val userKeysRepository: UserKeysRepository,
    private val notificationHelper: (String, String) -> Unit,
    private val stompClientProvider: () -> ChatStompClient,
    private val ratchetStatesRepository: RatchetStatesRepository,
    private val chatRoomRepository: ChatRoomRepository,
) {

    // Associated data used for AEAD operations
    private val AD: ByteArray = "MyChatAppV1".toByteArray()

    private lateinit var stompClient: ChatStompClient

    fun connect() {
        stompClient = ChatStompClient(
            serverUrl = "ws://192.168.1.10:8080/ws",
            accessToken = accessToken,
            onMessageReceived = { message ->
                println("New message: $message")

                // After receiving message, notify backend that it was delivered
                stompClient.sendDeliveredReceipt(
                    DeliveryReceiptRequest(
                        messageId = message.messageId,
                        senderId = message.senderId,
                        receiverId = message.receiverId
                    )
                )
            },
            onMessageStatusReceived = { ack ->
                println("Message status changed: $ack")
            },
            onConnected = {
                println("Connected to chat WebSocket")
            },
            onError = { error ->
                println("WebSocket error: $error")
            }
        )

        stompClient.connect()
    }

    suspend fun receiveIncomingMessage(encryptedMessage: ChatMessage) {
        try {
            // 1. Decrypt message body
            val message = encryptedMessage.message
            val senderId = encryptedMessage.receiverId
            val receiverId = encryptedMessage.senderId
            val sessionId = "${senderId}_${receiverId}"
            val user = userRepository.getUser()

            if (user?.userId == encryptedMessage.receiverId.toLong()) {
                val decryptedBody = when (message) {
                    is CryptoPreKeyMessage -> {
                        val preKeyBundleResult =
                            remoteUserRepository.getUserPreKeys(encryptedMessage.senderId)
                        val spk = spkRepository.getSpkById(message.spkId)
                        val userKeys = userKeysRepository.getUserKeys()

                        if (preKeyBundleResult is ApiResult.Success && spk != null) {
                            val preKeyBundle = preKeyBundleResult.data


                            // Build UserKeysDto expected by crypto module. userId is not provided by
                            // remote bundle here so we use 0L as a placeholder.
                            val userKeysDto = UserKeysDto(
                                userId = user.userId,
                                identityKey = userKeys?.identityKeyPrivate ?: ByteArray(0),
                                signedPreKey = Pair(spk.first, spk.second),
                                oneTimePreKeys = message.opkId?.let {
                                    opkRepository.getOneTimePreKeyById(it)?.privateKey
                                } ?: ByteArray(0)
                            )

                            val decryptDto = crypto.createDecryptedPreKeyMessageDto(
                                message,
                                AD,
                                userKeysDto
                            )

                            val result = crypto.decryptPreKeyMessage(decryptDto)

                            ratchetStatesRepository.updateRatchetState(
                                sessionId = sessionId,
                                ratchetState = result.newState
                            )


                            val remoteUser =
                                remoteUserRepository.getUserByUserId(receiverId.toLong())

                            if (remoteUser is ApiResult.Success) {
                                chatRoomRepository.insertChatRoom(
                                    ChatRoom(
                                        sessionId = sessionId,
                                        senderId = userRepository.getUser()!!,
                                        recipientId = Friends(
                                            userId = receiverId.toLong(),
                                            username = remoteUser.data.username,
                                            email = remoteUser.data.email
                                        )
                                    )
                                )
                            } else {
                                println("Failed to fetch remote user info for userId: $receiverId")
                            }




                            result.plaintext
                        } else {
                            "[Unable to fetch pre-key bundle or missing SPK]"
                        }
                    }

                    is RatchetMessage -> {
                        val ratchetState = ratchetStatesRepository
                            .getRatchetStateById(sessionId)?.toRatchetStateDto()

                        if (ratchetState != null) {
                            val decryptDto = DecryptMessageDto(
                                message = message,
                                associatedData = AD,
                                state = ratchetState
                            )

                            val result = crypto.decryptRatchetMessage(decryptDto)
                            ratchetStatesRepository.updateRatchetState(
                                sessionId = sessionId,
                                ratchetState = result.newState
                            )
                            result.plaintext

                        } else {
                            "[No existing session state for this sender]"
                        }
                    }

                    else -> {
                        "[Unsupported message type]"
                    }
                }

                // Convert ChatMessage.createdAt (LocalDateTime) to epoch millis
                val epochMillis = encryptedMessage.createdAt
                    .atZone(java.time.ZoneId.systemDefault())
                    .toInstant()
                    .toEpochMilli()


                val localMessage = Messages(
                    messageId = encryptedMessage.messageId,
                    sessionId = chatRoomRepository.getChatRoomBySessionId(sessionId)!!,
                    content = decryptedBody,
                    timestamp = epochMillis,
                    status = MessageStatus.RECEIVED,
                    isSentByUser = false
                )

                // 3. Save to Room
                messagesDao.insertMessage(localMessage)

                // 4. Tell backend message was delivered
                stompClientProvider().sendDeliveredReceipt(
                    DeliveryReceiptRequest(
                        messageId = encryptedMessage.messageId,
                        senderId = encryptedMessage.senderId,
                        receiverId = encryptedMessage.receiverId
                    )
                )

                // 5. Show notification (callback)
                notificationHelper(encryptedMessage.senderId, decryptedBody)
            } else {
                println("Received message intended for user ${encryptedMessage.receiverId}, but local user is ${user?.userId}")

            }

            } catch (e: Exception) {
            println("Error processing incoming message: ${e.message}")
        }
    }

    fun sendMessage(senderId: String, receiverId: String, content: String) {
        // Wrap the plain string into a RatchetMessage ciphertext for transport
        val outgoing = RatchetMessage(
            encryptedHeader = ByteArray(0),
            ciphertext = content.toByteArray()
        )

        stompClient.sendChatMessage(
            ChatRequest(
                senderId = senderId,
                receiverId = receiverId,
                message = outgoing
            )
        )
    }

    fun disconnect() {
        stompClient.disconnect()
    }
}
