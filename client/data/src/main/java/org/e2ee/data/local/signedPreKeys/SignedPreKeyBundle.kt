package org.e2ee.data.local.signedPreKeys

data class SignedPreKeyBundle(
    val keyId: String,
    val signedPreKey: ByteArray,
    val signature: ByteArray,
)