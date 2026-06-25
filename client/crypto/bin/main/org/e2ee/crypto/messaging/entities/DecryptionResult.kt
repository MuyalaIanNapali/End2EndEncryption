package org.e2ee.crypto.messaging.entities

import org.e2ee.common.PreKeyMessage
import org.e2ee.common.RatchetMessage
import org.e2ee.common.RatchetStateDto
import org.e2ee.common.UserKeysDecodedDecDto

data class DecryptionResult(
    val plaintext: String,
    val newState: RatchetStateDto
)

data class DecryptPreKeyMessageDto(
    val message: PreKeyMessage,
    val associatedData: ByteArray,
    val receiverKeyManager : UserKeysDecodedDecDto
)

data class DecryptMessageDto(
    val message: RatchetMessage,
    val associatedData: ByteArray,
    val state : RatchetStateDto
)
