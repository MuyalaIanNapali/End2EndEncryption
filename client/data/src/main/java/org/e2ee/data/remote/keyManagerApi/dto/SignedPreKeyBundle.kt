package org.e2ee.data.remote.keyManagerApi.dto

data class SignedPreKeyBundle(
    val keyId: Long,
    val signedPreKey: ByteArray,
    val signature: ByteArray,
)
