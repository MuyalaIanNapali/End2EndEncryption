package org.e2ee.crypto.entities

import org.e2ee.crypto.PreKeyMessage
import org.e2ee.crypto.RatchetMessage
import org.e2ee.crypto.doubleRatchet.RatchetStateHE
import org.e2ee.crypto.dto.UserKeysDecodedDto
import org.e2ee.crypto.x3dh.X3DHKeyManager

data class DecryptionResult(
    val plaintext: String,
    val newState: RatchetStateHE
)

data class DecryptPreKeyMessageDto(
    val message: PreKeyMessage,
    val associatedData: ByteArray,
    val receiverKeyManager : UserKeysDecodedDto
)

data class DecryptMessageDto(
    val message: RatchetMessage,
    val associatedData: ByteArray,
    val state : RatchetStateHE
)
