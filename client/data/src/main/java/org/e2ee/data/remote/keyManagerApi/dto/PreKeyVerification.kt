package org.e2ee.data.remote.keyManagerApi.dto

data class PreKeyVerification(
    val identityKeySigning: ByteArray,
    val signedPreKeyBundle: SignedPreKeyBundle,
)

data class PreKeyVerificationResult(
    val isValid: Boolean,
    val identitySigningKeyMatches: Boolean,
    val signedPreKeyMatches: Boolean,
    val signedPreKeyIdMatches: Boolean,
    val signatureValid: Boolean
)
