package org.e2ee.common

open class Message

data class PreKeyMessage(
    val IKs: ByteArray,
    val EKs: ByteArray,
    val DHs: ByteArray,
    val opkId: String?,
    val spkId : String,
    val ciphertext: ByteArray
) : Message()


data class RatchetMessage(
    val encryptedHeader: ByteArray,
    val ciphertext: ByteArray
) : Message()