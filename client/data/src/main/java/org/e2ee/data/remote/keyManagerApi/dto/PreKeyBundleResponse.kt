package org.e2ee.data.remote.keyManagerApi.dto

import org.e2ee.common.PreKeyBundle

data class PreKeyBundleResponse(
    val identityKey: ByteArray,

    val signedPreKeyBundle: SignedPreKeyBundle,

    val identityKeySigning: ByteArray,

    val opkPair: Pair<String, ByteArray>?
)

fun PreKeyBundleResponse.toPreKeyBundle(): PreKeyBundle {
    return PreKeyBundle(
        IKpub = identityKey,
        SPKpub = Pair(signedPreKeyBundle.keyId, signedPreKeyBundle.signedPreKey),
        OPKpub = opkPair?.let { mapOf(it.first to it.second) },
        signature = signedPreKeyBundle.signature,
        IKsigPub = identityKeySigning
    )
}
