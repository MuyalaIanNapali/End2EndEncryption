package org.e2ee.crypto.entities

import org.e2ee.common.Message
import org.e2ee.crypto.doubleRatchet.RatchetStateHE
import org.e2ee.common.UserKeysDecodedDto
import org.e2ee.common.PreKeyBundle
import org.e2ee.common.RatchetStateDto

data class EncryptionResult(
    val message: Message,
    val newState: RatchetStateDto
)

data class EncryptPreKeyMessageDto(
    val associatedData : ByteArray,
    val plainText: String,
    val receiverPreKeyBundle: PreKeyBundle,
    val senderPreKeyBundle: Pair<ByteArray, String>,
    val senderKeyManager : UserKeysDecodedDto
)

data class EncryptMessageDto(
    val associatedData: ByteArray,
    val plainText: String,
    val state: RatchetStateHE
)

