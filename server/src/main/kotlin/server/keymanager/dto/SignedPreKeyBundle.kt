package server.keymanager.dto

data class SignedPreKeyBundle(
    val keyId: String,
    val signedPreKey: ByteArray,
    val signature: ByteArray,
)
