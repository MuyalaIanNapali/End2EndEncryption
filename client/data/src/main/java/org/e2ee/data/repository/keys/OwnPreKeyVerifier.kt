package org.e2ee.data.repository.keys

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerification
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerificationResult
import org.e2ee.data.local.signedPreKeys.SignedPreKeyBundle
import org.e2ee.data.remote.util.fromBase64
import javax.inject.Inject

class OwnPreKeyVerifier @Inject constructor() {

    fun verifyOwnServerPreKeys(
        server: PreKeyVerification,
        localIdentitySigningPublicKey: ByteArray,
        localSignedPreKeyBundle: SignedPreKeyBundle,
        verifySignature: (
            publicKey: ByteArray,
            message: ByteArray,
            signature: ByteArray
        ) -> Boolean
    ): PreKeyVerificationResult {

        val identitySigningKeyMatches =
            (server.identityKeySigning.fromBase64()).contentEquals(localIdentitySigningPublicKey)

        val signedPreKeyIdMatches =
            server.signedPreKeyBundleDto.keyId == localSignedPreKeyBundle.keyId

        val signedPreKeyMatches =
            (server.signedPreKeyBundleDto.signedPreKey.fromBase64()).contentEquals(
                localSignedPreKeyBundle.signedPreKey
            )

        val signatureValid =
            if (identitySigningKeyMatches && signedPreKeyMatches) {
                verifySignature(
                    server.identityKeySigning.fromBase64(),
                    server.signedPreKeyBundleDto.signedPreKey.fromBase64(),
                    server.signedPreKeyBundleDto.signature.fromBase64()
                )
            } else {
                false
            }

        val isValid =
            identitySigningKeyMatches &&
                    signedPreKeyIdMatches &&
                    signedPreKeyMatches &&
                    signatureValid

        return PreKeyVerificationResult(
            isValid = isValid,
            identitySigningKeyMatches = identitySigningKeyMatches,
            signedPreKeyMatches = signedPreKeyMatches,
            signedPreKeyIdMatches = signedPreKeyIdMatches,
            signatureValid = signatureValid
        )
    }
}