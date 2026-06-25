package org.e2ee.crypto.messaging.entities

import org.e2ee.common.Message
import org.e2ee.crypto.messaging.doubleRatchet.RatchetStateHE
import org.e2ee.common.PreKeyBundle
import org.e2ee.common.RatchetStateDto
import org.e2ee.common.UserKeysDecodedEncDto

data class EncryptionResult(
    val message: Message,
    val newState: RatchetStateDto
)

data class EncryptPreKeyMessageDto(
    val associatedData : ByteArray,
    val plainText: String,
    val receiverPreKeyBundle: PreKeyBundle,
    val senderPreKeyBundle: Pair<ByteArray, String>,
    val senderKeyManager : UserKeysDecodedEncDto
)

data class EncryptMessageDto(
    val associatedData: ByteArray,
    val plainText: String,
    val state: RatchetStateHE
)

