package org.e2ee.crypto.dto

import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import java.security.KeyPair
import java.security.PrivateKey

data class UserKeysDto(
    val userId: Long,
    val identityKey: ByteArray,
    val signedPreKey: Pair<ByteArray, ByteArray>,
    val oneTimePreKeys: ByteArray?= null
)

data class UserKeysDecodedDto(
    val userId: Long,
    val identityKey: PrivateKey,
    val signedPreKey: KeyPair,
    val oneTimePreKeys: PrivateKey?=null
)

fun UserKeysDto.toDecodedDto(): UserKeysDecodedDto {
    val crypto = EncryptionAndDecryptionUtility()

    return UserKeysDecodedDto(
        userId = userId,
        identityKey = crypto.decodePrivateKey(identityKey),
        signedPreKey = KeyPair(
            crypto.decodePublicKey(signedPreKey.first),
            crypto.decodePrivateKey(signedPreKey.second)
        ),
        oneTimePreKeys = oneTimePreKeys?.let {
            crypto.decodePrivateKey(it)
        }
    )
}

