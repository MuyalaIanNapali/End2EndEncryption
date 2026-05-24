package org.e2ee.common

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf

enum class EncodedMessageType {
    PRE_KEY_MESSAGE,
    RATCHET_MESSAGE
}

object MessageProtoCodec {

    @OptIn(ExperimentalSerializationApi::class)
    fun encode(message: Message): ByteArray {
        return when (message) {
            is PreKeyMessage -> ProtoBuf.encodeToByteArray(message)
            is RatchetMessage -> ProtoBuf.encodeToByteArray(message)
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    fun decode(
        messageType: EncodedMessageType,
        bytes: ByteArray
    ): Message {
        return when (messageType) {
            EncodedMessageType.PRE_KEY_MESSAGE ->
                ProtoBuf.decodeFromByteArray<PreKeyMessage>(bytes)

            EncodedMessageType.RATCHET_MESSAGE ->
                ProtoBuf.decodeFromByteArray<RatchetMessage>(bytes)
        }
    }
}