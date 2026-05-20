package org.e2ee.data.remote.keyManagerApi.dto

data class PreKeyVerification(
    val identityKeySigning: ByteArray,
    val signedPreKeyBundle: SignedPreKeyBundle,
)
