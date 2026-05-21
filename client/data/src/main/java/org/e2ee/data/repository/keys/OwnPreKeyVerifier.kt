package org.e2ee.data.repository.keys

import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerification
import org.e2ee.data.remote.keyManagerApi.dto.PreKeyVerificationResult
import org.e2ee.data.remote.keyManagerApi.dto.SignedPreKeyBundle

class OwnPreKeyVerifier {

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
            server.identityKeySigning.contentEquals(localIdentitySigningPublicKey)

        val signedPreKeyIdMatches =
            server.signedPreKeyBundle.keyId == localSignedPreKeyBundle.keyId

        val signedPreKeyMatches =
            server.signedPreKeyBundle.signedPreKey.contentEquals(
                localSignedPreKeyBundle.signedPreKey
            )

        val signatureValid =
            if (identitySigningKeyMatches && signedPreKeyMatches) {
                verifySignature(
                    server.identityKeySigning,
                    server.signedPreKeyBundle.signedPreKey,
                    server.signedPreKeyBundle.signature
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