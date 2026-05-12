package server.keymanager.dto

data class SignedPreKeyBundle(
    val keyId: Long,
    val signedPreKey: ByteArray,
    val signature: ByteArray,
)
