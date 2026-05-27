package org.e2ee.data.remote.keyManagerApi.dto

import org.e2ee.data.local.signedPreKeys.SignedPreKeyBundle

data class PreKeyVerification(
    val identityKeySigning: String,
    val signedPreKeyBundleDto: SignedPreKeyBundleDto,
)

data class PreKeyVerificationResult(
    val isValid: Boolean,
    val identitySigningKeyMatches: Boolean,
    val signedPreKeyMatches: Boolean,
    val signedPreKeyIdMatches: Boolean,
    val signatureValid: Boolean
)


