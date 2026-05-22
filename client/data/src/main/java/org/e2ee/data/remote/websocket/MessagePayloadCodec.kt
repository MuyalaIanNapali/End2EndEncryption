package org.e2ee.data.remote.websocket

import android.util.Base64
import org.e2ee.common.EncodedMessageType
import org.e2ee.common.Message
import org.e2ee.common.MessageProtoCodec

object MessagePayloadCodec {

    fun encodeToBase64(message: Message): String {
        val protobufBytes = MessageProtoCodec.encode(message)

        return Base64.encodeToString(
            protobufBytes,
            Base64.NO_WRAP
        )
    }

    fun decodeFromBase64(
        messageType: MessageType,
        encodedMessage: String
    ): Message {
        val protobufBytes = Base64.decode(
            encodedMessage,
            Base64.NO_WRAP
        )

        return MessageProtoCodec.decode(
            messageType = messageType.toEncodedMessageType(),
            bytes = protobufBytes
        )
    }

    private fun MessageType.toEncodedMessageType(): EncodedMessageType {
        return when (this) {
            MessageType.PRE_KEY_MESSAGE -> EncodedMessageType.PRE_KEY_MESSAGE
            MessageType.RATCHET_MESSAGE -> EncodedMessageType.RATCHET_MESSAGE
        }
    }
}