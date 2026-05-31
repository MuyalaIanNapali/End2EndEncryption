package org.e2ee.common

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class UserKeysDto(
    val userId: Long,
    val identityKey: ByteArray,
    val signedPreKey: Pair<ByteArray, ByteArray>,
    val oneTimePreKeys: ByteArray?= null
)

data class UserKeysDecodedDecDto(
    val userId: Long,
    val identityKey: PrivateKey,
    val signedPreKey: KeyPair,
    val oneTimePreKeys: PrivateKey?=null
)


data class UserKeysDecodedEncDto(
    val userId: Long,
    val identityKey: PrivateKey,
    val signedPreKey: KeyPair,
    val oneTimePreKeys: PublicKey?=null
)
