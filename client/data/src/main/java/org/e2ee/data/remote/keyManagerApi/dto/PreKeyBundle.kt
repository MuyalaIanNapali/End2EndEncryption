package org.e2ee.data.remote.keyManagerApi.dto

data class PreKeyBundleDto(
    var userId: Long? = null,

    val identityKey: ByteArray,

    val signedPreKeyBundle: SignedPreKeyBundle,

    val identityKeySigning: ByteArray,

    val opkMap: Map<String, ByteArray>,
)

