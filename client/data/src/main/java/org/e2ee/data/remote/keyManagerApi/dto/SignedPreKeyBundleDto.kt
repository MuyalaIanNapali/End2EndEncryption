package org.e2ee.data.remote.keyManagerApi.dto

data class SignedPreKeyBundleDto(
    val keyId: String,
    val signedPreKey: String,
    val signature: String,
)