package org.e2ee.crypto.entities

import org.e2ee.common.PreKeyMessage
import org.e2ee.common.RatchetMessage
import org.e2ee.common.RatchetStateDto
import org.e2ee.crypto.doubleRatchet.RatchetStateHE
import org.e2ee.common.UserKeysDecodedDto

data class DecryptionResult(
    val plaintext: String,
    val newState: RatchetStateDto
)

data class DecryptPreKeyMessageDto(
    val message: PreKeyMessage,
    val associatedData: ByteArray,
    val receiverKeyManager : UserKeysDecodedDto
)

data class DecryptMessageDto(
    val message: RatchetMessage,
    val associatedData: ByteArray,
    val state : RatchetStateDto
)
