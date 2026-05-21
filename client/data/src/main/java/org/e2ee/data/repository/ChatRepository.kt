package org.e2ee.data.repository

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.e2ee.common.Message
import org.e2ee.crypto.Crypto
import org.e2ee.common.PreKeyMessage
import org.e2ee.data.local.chatRoom.ChatRoom
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
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.local.ratchetStates.toRatchetStateDto
import org.e2ee.data.remote.keyManagerApi.dto.toPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.websocket.ChatMessage
import org.e2ee.data.remote.websocket.ChatRequest
import org.e2ee.data.remote.websocket.ChatStompClient
import org.e2ee.data.remote.websocket.DeliveryReceiptRequest
import org.e2ee.data.remote.websocket.MessageType

class ChatRepository(
    private val accessToken: String,
    private val messagesDao: MessagesDao,
    private val crypto : Crypto,
    private val userRepository: LocalUserRepository,
    private val spkRepository: SignedPreKeysRepository,
    private val remoteUserRepository: RemoteUserRepository,
    private val opkRepository : OneTimePreKeysRepository,
    private val userKeysRepository: UserKeysRepository,
    private val notificationHelper: (String, String) -> Unit, ///update later to MessageNotifier
    private val ratchetStatesRepository: RatchetStatesRepository,
    private val chatRoomRepository: ChatRoomRepository,
    private val messagesRepository: MessagesRepository
) {

    // Associated data used for AEAD operations
    private val AD: ByteArray = "MyChatAppV1".toByteArray()

    private val repositoryScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var stompClient: ChatStompClient

    fun observeMessages(sessionId: String): kotlinx.coroutines.flow.Flow<List<Messages>> {
        return messagesRepository.observeMessagesBySessionId(sessionId)
    }

    fun connect() {
        stompClient = ChatStompClient(
            serverUrl = "ws://192.168.1.10:5000/ws",
            accessToken = accessToken,

            onMessageReceived = { message ->
                repositoryScope.launch {
                    receiveIncomingMessage(message)
                }
            },

            onMessageStatusReceived = { ack ->
                repositoryScope.launch {
                    when (ack.status) {
                        org.e2ee.data.remote.websocket.MessageStatus.SENT -> {
                            messagesRepository.updateStatus(
                                remoteMessageId = ack.messageId,
                                status = MessageStatus.SENT
                            )
                        }

                        org.e2ee.data.remote.websocket.MessageStatus.DELIVERED -> {
                            messagesRepository.updateStatus(
                                remoteMessageId = ack.messageId,
                                status = MessageStatus.DELIVERED
                            )
                        }

                        org.e2ee.data.remote.websocket.MessageStatus.FAILED -> {
                            messagesRepository.updateStatus(
                                remoteMessageId = ack.messageId,
                                status = MessageStatus.FAILED
                            )
                        }

                        else -> Unit
                    }
                }
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
            val localUser = encryptedMessage.receiverId
            val otherUser = encryptedMessage.senderId
            val sessionId = "${localUser}_${otherUser}"
            val user = userRepository.getUser()
                ?: throw IllegalStateException("No local user found for incoming message decryption")

            if (user.userId == encryptedMessage.receiverId.toLong()) {
                val decryptedBody = when (encryptedMessage.messageType) {
                    MessageType.PRE_KEY_MESSAGE -> {
                        val message = encryptedMessage.message as PreKeyMessage

                        val spk = spkRepository.getSpkById(message.spkId)
                        val userKeys = userKeysRepository.getUserKeys()
                            ?: throw IllegalStateException(
                                "User keys not found for incoming pre-key message decryption"
                            )
                        val opk = message.opkId?.let { opkRepository.getOneTimePreKeyById(it) }

                        if (spk != null) {
                            // Build UserKeysDto expected by crypto module. userId is not provided by
                            // remote bundle here so we use 0L as a placeholder.
                            val userKeysDto = UserKeysDto(
                                userId = user.userId,
                                identityKey = userKeys.identityKeyPrivate ,
                                signedPreKey = Pair(spk.first, spk.second),
                                oneTimePreKeys = opk?.privateKey
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
                                remoteUserRepository.getUserByUserId(otherUser.toLong())

                            if (remoteUser is ApiResult.Success) {
                                chatRoomRepository.insertChatRoom(
                                    ChatRoom(
                                        sessionId = sessionId,
                                        senderId = userRepository.getUser()!!.userId,
                                        recipientId = otherUser.toLong(),
                                    )
                                )
                            } else {
                                println(
                                    "Failed to fetch remote user message: $remoteUser"
                                )
                            }

                            message.opkId?.let { opkId ->
                                opkRepository.deleteOneTimePreKeyById(opkId)
                            }
                            result.plaintext
                        } else {
                            throw IllegalStateException(
                                "Failed to fetch pre-key bundle or SPK for incoming message decryption"
                            )
                        }
                    }

                    MessageType.RATCHET_MESSAGE -> {
                        val message = encryptedMessage.message as RatchetMessage

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
                            throw IllegalStateException(
                                "No ratchet state found for session $sessionId"
                            )
                        }
                    }
                }

                // Convert ChatMessage.createdAt (LocalDateTime) to epoch millis
                val epochMillis =encryptedMessage
                    .createdAt
                    ?.let { java.time.LocalDateTime.parse(it) }
                    ?.atZone(java.time.ZoneId.systemDefault())
                    ?.toInstant()?.toEpochMilli()
                    ?: System.currentTimeMillis()

                val chatRoom = createOrFetchChatRoom(
                    sessionId = sessionId,
                    localUser = user,
                    otherUserId = otherUser
                )


                val localMessage = Messages(
                    remoteMessageId = encryptedMessage.messageId,
                    sessionId = chatRoom.sessionId,
                    content = decryptedBody,
                    timestamp = epochMillis,
                    status = MessageStatus.RECEIVED,
                    isSentByUser = false
                )

                // 3. Save to Room
                messagesDao.insertMessage(localMessage)

                // 4. Tell backend message was delivered
                stompClient.sendDeliveredReceipt(
                    DeliveryReceiptRequest(
                        messageId = encryptedMessage.messageId,
                        senderId = encryptedMessage.senderId,
                        receiverId = encryptedMessage.receiverId
                    )
                )

                // 5. Show notification (callback)
                notificationHelper(encryptedMessage.senderId, decryptedBody)
            } else {
                println("Received message intended for user ${encryptedMessage.receiverId}, but local user is ${user.userId}")

            }

            } catch (e: Exception) {
            println("Error processing incoming message: ${e.message}")
        }
    }

    suspend fun sendMessage(receiverId: String, content: String) {
        val senderId = userRepository.getUser()?.userId?.toString() ?: return
        val messageId = java.util.UUID.randomUUID().toString()

        val sessionId = "${senderId}_${receiverId}"

        val chatRoom = chatRoomRepository.getChatRoomBySessionId(sessionId)

        val encryptedOutgoingMessage = if (chatRoom != null) {
            val ratchetState =
                ratchetStatesRepository.getRatchetStateById(sessionId)?.toRatchetStateDto()

            if (ratchetState != null) {
                val encryptedMessage = crypto.encryptRatchetMessage(
                    encryptionDto = crypto.createEncryptedMessageDto(
                        associatedData = AD,
                        plainText = content,
                        state = ratchetState
                    )
                )

                ratchetStatesRepository.updateRatchetState(
                    sessionId = sessionId,
                    ratchetState = encryptedMessage.newState
                )

                encryptedMessage.message
            } else {
                createPreKeyMessageAndSession(sessionId, senderId, receiverId, content)
            }
        } else {
            createPreKeyMessageAndSession(sessionId, senderId, receiverId, content)
        }

        val existingRoom = createOrFetchChatRoom(
            sessionId = sessionId,
            localUser = userRepository.getUser()!!,
            otherUserId = receiverId
        )
        messagesRepository.insertMessage(
            Messages(
                localId = 0L,
                remoteMessageId = messageId,
                sessionId = existingRoom.sessionId,
                content = content,
                timestamp = System.currentTimeMillis(),
                status = MessageStatus.SENDING,
                isSentByUser = true
            )
        )

        val messageType = when(encryptedOutgoingMessage) {
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
                createdAt = java.time.LocalDateTime.now().toString()
            )
        )
    }

    fun disconnect() {
        stompClient.disconnect()
    }
    private suspend fun createPreKeyMessageAndSession(
        sessionId: String,
        senderId: String,
        receiverId: String,
        content: String
    ): Message {
        val remoteUserResult = remoteUserRepository.getUserByUserId(receiverId.toLong())
        val preKeyBundleResult = remoteUserRepository.getUserPreKeys(receiverId)
        val spk = spkRepository.getFullActiveSignedPreKey()
        val userKeys = userKeysRepository.getUserKeys()

        if (
            remoteUserResult !is ApiResult.Success ||
            preKeyBundleResult !is ApiResult.Success ||
            spk == null ||
            userKeys == null
        ) {
            throw IllegalStateException("Cannot create pre-key session")
        }

        val remoteUser = remoteUserResult.data

        val userKeysDto = UserKeysDto(
            userId = senderId.toLong(),
            identityKey = userKeys.identityKeyPrivate,
            signedPreKey = Pair(spk.publicKey, spk.privateKey),
            oneTimePreKeys = preKeyBundleResult.data.opkPair?.second
        )

        val encryptedMessage = crypto.encryptPreKeyMessage(
            encryptionDto = crypto.createEncryptedPreKeyMessageDto(
                associatedData = AD,
                plainText = content,
                receiverPreKeyBundle = preKeyBundleResult.data.toPreKeyBundle(),
                senderPreKeyBundle = Pair(
                    userKeys.identityKeyPublic,
                    spk.signedPreKeyId
                ),
                senderKeyManager = userKeysDto
            )
        )

        ratchetStatesRepository.updateRatchetState(
            sessionId = sessionId,
            ratchetState = encryptedMessage.newState
        )

        val senderId = userRepository.getUser()?.userId
            ?: throw IllegalStateException("No local user found for chat session creation")

        chatRoomRepository.insertChatRoom(
            ChatRoom(
                sessionId = sessionId,
                senderId = senderId,
                recipientId = receiverId.toLong(),
            )
        )

        return encryptedMessage.message
    }


    private suspend fun createOrFetchChatRoom(
        sessionId: String,
        localUser: User,
        otherUserId: String
    ): ChatRoom {
        val existingRoom = chatRoomRepository.getChatRoomBySessionId(sessionId)

        if (existingRoom != null) {
            return existingRoom
        }

        val remoteUserResult = remoteUserRepository.getUserByUserId(otherUserId.toLong())

        if (remoteUserResult !is ApiResult.Success) {
            throw IllegalStateException("Failed to fetch remote user for chat room: $otherUserId")
        }

        val remoteUser = remoteUserResult.data

        val newChatRoom = ChatRoom(
            sessionId = sessionId,
            senderId = localUser.userId,
            recipientId =otherUserId.toLong()
        )

        chatRoomRepository.insertChatRoom(newChatRoom)

        return chatRoomRepository.getChatRoomBySessionId(sessionId)
            ?: throw IllegalStateException("Chat room was inserted but could not be fetched: $sessionId")
    }
}
