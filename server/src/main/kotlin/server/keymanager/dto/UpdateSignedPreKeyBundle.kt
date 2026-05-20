package server.keymanager.dto

data class UpdateSignedPreKeyBundle(
    val userId: Long,
    val keyId: String,
    val signedPreKey: ByteArray,
    val signature: ByteArray
)
