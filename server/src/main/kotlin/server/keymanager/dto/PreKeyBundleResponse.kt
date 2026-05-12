package server.keymanager.dto

data class PreKeyBundleResponse(
    val identityKey: ByteArray,

    val signedPreKeyBundle: SignedPreKeyBundle,

    val identityKeySigning: ByteArray,

    val opkPair: Pair<String, ByteArray>?
)
