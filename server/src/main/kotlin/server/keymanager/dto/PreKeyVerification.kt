package server.keymanager.dto

data class PreKeyVerification(
    val identityKeySigning: ByteArray,
    val signedPreKeyBundle: SignedPreKeyBundle,
)
