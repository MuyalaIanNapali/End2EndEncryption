package org.e2ee.data.repository.chat

import org.e2ee.common.Message
import org.e2ee.common.PreKeyMessage
import org.e2ee.common.RatchetMessage
import org.e2ee.common.UserKeysDto
import org.e2ee.crypto.Crypto
import org.e2ee.crypto.entities.DecryptMessageDto
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.ratchetStates.RatchetStatesRepository
import org.e2ee.data.local.ratchetStates.toRatchetStateDto
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.dto.toPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.websocket.ChatMessage
import org.e2ee.data.remote.websocket.MessageType

class ChatCryptoManager(
    private val crypto: Crypto,
    private val spkRepository: SignedPreKeysRepository,
    private val opkRepository: OneTimePreKeysRepository,
    private val userKeysRepository: UserKeysRepository,
    private val ratchetStatesRepository: RatchetStatesRepository,
    private val remoteUserRepository: RemoteUserRepository
) {

    private val associatedData: ByteArray = "MyChatAppV1".toByteArray()

    suspend fun decryptIncomingMessage(
        encryptedMessage: ChatMessage,
        sessionId: String,
        localUserId: Long
    ): String {
        return when (encryptedMessage.messageType) {
            MessageType.PRE_KEY_MESSAGE -> {
                decryptPreKeyMessage(
                    encryptedMessage = encryptedMessage,
                    sessionId = sessionId,
                    localUserId = localUserId
                )
            }

            MessageType.RATCHET_MESSAGE -> {
                decryptRatchetMessage(
                    encryptedMessage = encryptedMessage,
                    sessionId = sessionId
                )
            }
        }
    }

    suspend fun encryptOutgoingMessage(
        sessionId: String,
        senderId: String,
        receiverId: String,
        content: String
    ): Message {
        val existingRatchetState = ratchetStatesRepository
            .getRatchetStateById(sessionId)
            ?.toRatchetStateDto()

        return if (existingRatchetState != null) {
            val encryptedMessage = crypto.encryptRatchetMessage(
                encryptionDto = crypto.createEncryptedMessageDto(
                    associatedData = associatedData,
                    plainText = content,
                    state = existingRatchetState
                )
            )

            ratchetStatesRepository.updateRatchetState(
                sessionId = sessionId,
                ratchetState = encryptedMessage.newState
            )

            encryptedMessage.message
        } else {
            createPreKeyMessageAndSession(
                sessionId = sessionId,
                senderId = senderId,
                receiverId = receiverId,
                content = content
            )
        }
    }

    private suspend fun decryptPreKeyMessage(
        encryptedMessage: ChatMessage,
        sessionId: String,
        localUserId: Long
    ): String {
        val message = encryptedMessage.message as? PreKeyMessage
            ?: throw IllegalStateException("Expected PreKeyMessage")

        val spk = spkRepository.getSpkById(message.spkId)
            ?: throw IllegalStateException("Signed pre-key not found: ${message.spkId}")

        val userKeys = userKeysRepository.getUserKeys()
            ?: throw IllegalStateException("User keys not found")

        val opk = message.opkId?.let {
            opkRepository.getOneTimePreKeyById(it)
        }

        val userKeysDto = UserKeysDto(
            userId = localUserId,
            identityKey = userKeys.identityKeyPrivate,
            signedPreKey = Pair(spk.first, spk.second),
            oneTimePreKeys = opk?.privateKey
        )

        val decryptDto = crypto.createDecryptedPreKeyMessageDto(
            message,
            associatedData,
            userKeysDto
        )

        val result = crypto.decryptPreKeyMessage(decryptDto)

        ratchetStatesRepository.updateRatchetState(
            sessionId = sessionId,
            ratchetState = result.newState
        )

        message.opkId?.let { opkId ->
            opkRepository.deleteOneTimePreKeyById(opkId)
        }

        return result.plaintext
    }

    private suspend fun decryptRatchetMessage(
        encryptedMessage: ChatMessage,
        sessionId: String
    ): String {
        val message = encryptedMessage.message as? RatchetMessage
            ?: throw IllegalStateException("Expected RatchetMessage")

        val ratchetState = ratchetStatesRepository
            .getRatchetStateById(sessionId)
            ?.toRatchetStateDto()
            ?: throw IllegalStateException("No ratchet state found for session $sessionId")

        val decryptDto = DecryptMessageDto(
            message = message,
            associatedData = associatedData,
            state = ratchetState
        )

        val result = crypto.decryptRatchetMessage(decryptDto)

        ratchetStatesRepository.updateRatchetState(
            sessionId = sessionId,
            ratchetState = result.newState
        )

        return result.plaintext
    }

    private suspend fun createPreKeyMessageAndSession(
        sessionId: String,
        senderId: String,
        receiverId: String,
        content: String
    ): Message {
        val preKeyBundleResult = remoteUserRepository.getUserPreKeys(receiverId)

        val spk = spkRepository.getFullActiveSignedPreKey()
        val userKeys = userKeysRepository.getUserKeys()

        if (
            preKeyBundleResult !is ApiResult.Success ||
            spk == null ||
            userKeys == null
        ) {
            throw IllegalStateException("Cannot create pre-key session")
        }

        val userKeysDto = UserKeysDto(
            userId = senderId.toLong(),
            identityKey = userKeys.identityKeyPrivate,
            signedPreKey = Pair(spk.publicKey, spk.privateKey),
            oneTimePreKeys = preKeyBundleResult.data.opkPair?.second
        )

        val encryptedMessage = crypto.encryptPreKeyMessage(
            encryptionDto = crypto.createEncryptedPreKeyMessageDto(
                associatedData = associatedData,
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

        return encryptedMessage.message
    }
}