package org.e2ee.data.remote.keyManagerApi.dto

data class UpdateSignedPreKeyBundle(
    val userId: Long,
    val keyId: Long,
    val signedPreKey: ByteArray,
    val signature: ByteArray
)
