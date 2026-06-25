package org.e2ee.common

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.protobuf.ProtoNumber

@Serializable
sealed class Message

@Serializable
data class PreKeyMessage @OptIn(ExperimentalSerializationApi::class) constructor(
    @ProtoNumber(1)
    val IKs: ByteArray,

    @ProtoNumber(2)
    val EKs: ByteArray,

    @ProtoNumber(3)
    val DHs: ByteArray,

    @ProtoNumber(4)
    val opkId: String?,

    @ProtoNumber(5)
    val spkId: String,

    @ProtoNumber(6)
    val ciphertext: ByteArray
) : Message()

@Serializable
data class RatchetMessage(
    @ProtoNumber(1)
    val encryptedHeader: ByteArray,

    @ProtoNumber(2)
    val ciphertext: ByteArray
) : Message()