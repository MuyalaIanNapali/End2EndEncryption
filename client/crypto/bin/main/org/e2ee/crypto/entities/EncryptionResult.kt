package org.e2ee.crypto.entities

import org.e2ee.crypto.Message
import org.e2ee.crypto.PreKeyMessage
import org.e2ee.crypto.doubleRatchet.RatchetStateHE
import org.e2ee.crypto.dto.UserKeysDecodedDto
import org.e2ee.crypto.x3dh.PreKeyBundle
import org.e2ee.crypto.x3dh.X3DHKeyManager

data class EncryptionResult(
    val message: Message,
    val newState: RatchetStateHE
)

data class EncryptPreKeyMessageDto(
    val associatedData : ByteArray,
    val plainText: String,
    val receiverPreKeyBundle: PreKeyBundle,
    val senderPreKeyBundle: PreKeyBundle,
    val senderKeyManager : UserKeysDecodedDto
)

data class EncryptMessageDto(
    val associatedData: ByteArray,
    val plainText: String,
    val state: RatchetStateHE
)

