package org.e2ee.data.repository.chat

import android.util.Log
import org.e2ee.common.Message
import org.e2ee.common.PreKeyMessage
import org.e2ee.common.RatchetMessage
import org.e2ee.common.UserKeysDto
import org.e2ee.crypto.messaging.Crypto
import org.e2ee.crypto.messaging.entities.DecryptMessageDto
import org.e2ee.data.local.opk.OneTimePreKeysRepository
import org.e2ee.data.local.ratchetStates.RatchetStatesRepository
import org.e2ee.data.local.ratchetStates.toRatchetStateDto
import org.e2ee.data.local.signedPreKeys.SignedPreKeysRepository
import org.e2ee.data.local.userKeys.UserKeysRepository
import org.e2ee.data.remote.keyManagerApi.dto.toPreKeyBundle
import org.e2ee.data.remote.network.ApiResult
import org.e2ee.data.remote.users.RemoteUserRepository
import org.e2ee.data.remote.util.toBase64
import org.e2ee.data.remote.websocket.ChatMessage
import org.e2ee.data.remote.websocket.MessagePayloadCodec
import org.e2ee.data.remote.websocket.MessageType
import javax.inject.Inject

class ChatCryptoManager @Inject constructor(
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
        Log.d("ChatCryptoManager", "Decrypting message with sessionId: $sessionId for localUserId: $localUserId, messageType: ${encryptedMessage.messageType}")
        val decodedMessage = MessagePayloadCodec.decodeFromBase64(
            messageType = encryptedMessage.messageType,
            encodedMessage = encryptedMessage.encodedMessage
        )

        Log.d("ChatCryptoManager", "Decoded message: $decodedMessage for sessionId: $sessionId")

        return when (encryptedMessage.messageType) {
            MessageType.PRE_KEY_MESSAGE -> {
                Log.d("ChatCryptoManager", "Processing PreKeyMessage for sessionId: $sessionId")

                val message = decodedMessage as? PreKeyMessage
                    ?: throw IllegalStateException("Expected PreKeyMessage")

                decryptPreKeyMessage(
                    message = message,
                    sessionId = sessionId,
                    localUserId = localUserId
                )
            }

            MessageType.RATCHET_MESSAGE -> {
                Log.d("ChatCryptoManager", "Processing RatchetMessage for sessionId: $sessionId")
                val message = decodedMessage as? RatchetMessage
                    ?: throw IllegalStateException("Expected RatchetMessage")

                decryptRatchetMessage(
                    message = message,
                    sessionId = sessionId
                )
            }
        }
    }

    suspend fun encryptOutgoingMessage(
        sessionId: String,
        senderId: String,
        receiverUsername: String,
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
                receiverUsername = receiverUsername,
                content = content
            )
        }
    }

    private suspend fun decryptPreKeyMessage(
        message: PreKeyMessage,
        sessionId: String,
        localUserId: Long
    ): String {
        Log.d("ChatCryptoManager", "Decrypting PreKeyMessage for sessionId: $sessionId, localUserId: $localUserId")

        val localSpk = spkRepository.getAllSignedPreKeys()
        Log.d("ChatMessageSender", "Local signed pre-keys: ${localSpk.map { it.signedPreKeyId}}")

        Log.d("ChatCryptoManager", "Fetching SPK for sessionId: $sessionId, spkId: ${message.spkId}")
        val spk = spkRepository.getSpkById(message.spkId)
            ?: throw IllegalStateException("Signed pre-key not found: ${message.spkId}")

        Log.d("ChatCryptoManager", "Fetched SPK for sessionId: $sessionId, spkId: ${message.spkId}")
        val userKeys = userKeysRepository.getUserKeys()
            ?: throw IllegalStateException("User keys not found")

        Log.d("ChatCryptoManager", "Fetched user keys for sessionId: $sessionId, localUserId: $localUserId")
        val opk = message.opkId?.let {
            opkRepository.getOneTimePreKeyById(it)
        }

        Log.d("ChatCryptoManager", "Fetched OPK for sessionId: $sessionId, opkId: ${message.opkId}")
        val userKeysDto = UserKeysDto(
            userId = localUserId,
            identityKey = userKeys.identityKeyPrivate,
            signedPreKey = Pair(spk.first, spk.second),
            oneTimePreKeys = opk?.privateKey
        )

        Log.d("ChatCryptoManager", "Constructed UserKeysDto for sessionId: $sessionId, localUserId: $localUserId, userKeysDto: $userKeysDto")
        val decryptDto = crypto.createDecryptedPreKeyMessageDto(
            message,
            associatedData,
            userKeysDto
        )
        Log.d("ChatCryptoManager", "Created DecryptPreKeyMessageDto for sessionId: $sessionId, localUserId: $localUserId, decryptDto: $decryptDto")

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
        message: RatchetMessage,
        sessionId: String
    ): String {
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
        receiverUsername: String,
        content: String
    ): Message {
        val preKeyBundleResult = remoteUserRepository.getUserPreKeys(receiverUsername)

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
            oneTimePreKeys = preKeyBundleResult.data.opkPair?.second?.toBase64()
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