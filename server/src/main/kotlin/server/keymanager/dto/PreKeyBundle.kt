package server.keymanager.dto

data class PreKeyBundle(
    var userId: Long? = null,

    val identityKey: ByteArray,

    val signedPreKeyBundle: SignedPreKeyBundle,

    val identityKeySigning: ByteArray,

    val opkMap: Map<String, ByteArray>,
)
