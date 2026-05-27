package org.e2ee.data.remote.keyManagerApi.dto

import org.e2ee.data.local.signedPreKeys.SignedPreKeyBundle

data class PreKeyBundleDto(
    var userId: Long? = null,

    val identityKey: ByteArray,

    val signedPreKeyBundle: SignedPreKeyBundle,

    val identityKeySigning: ByteArray,

    val opkMap: Map<String, ByteArray>,
)

