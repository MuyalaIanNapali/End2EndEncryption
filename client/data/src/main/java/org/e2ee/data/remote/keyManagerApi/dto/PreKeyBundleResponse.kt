package org.e2ee.data.remote.keyManagerApi.dto

import org.e2ee.common.PreKeyBundle
import org.e2ee.data.local.signedPreKeys.SignedPreKeyBundle
import org.e2ee.data.remote.util.toBase64

data class PreKeyBundleResponse(
    val identityKey: String,

    val signedPreKeyBundle: SignedPreKeyBundleDto,

    val identityKeySigning: String,

    val opkPair: Pair<String, String>?
)

fun PreKeyBundleResponse.toPreKeyBundle(): PreKeyBundle {
    return PreKeyBundle(
        IKpub = identityKey.toBase64(),
        SPKpub = Pair(signedPreKeyBundle.keyId, signedPreKeyBundle.signedPreKey.toBase64()),
        OPKpub = opkPair?.let { mapOf(it.first to it.second.toBase64()) },
        signature = signedPreKeyBundle.signature.toBase64(),
        IKsigPub = identityKeySigning.toBase64()
    )
}
