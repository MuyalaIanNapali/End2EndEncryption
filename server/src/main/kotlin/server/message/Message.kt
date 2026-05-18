package server.message

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo

@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = "type"
)
@JsonSubTypes(
    JsonSubTypes.Type(value = PreKeyMessage::class, name = "pre_key"),
    JsonSubTypes.Type(value = RatchetMessage::class, name = "ratchet")
)
sealed class Message

data class PreKeyMessage(
    val IKs: ByteArray,
    val EKs: ByteArray,
    val DHs: ByteArray,
    val opkId: String?,
    val ciphertext: ByteArray
) : Message()

data class RatchetMessage(
    val encryptedHeader: ByteArray,
    val ciphertext: ByteArray
) : Message()