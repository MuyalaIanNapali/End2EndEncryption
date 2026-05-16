package org.e2ee.crypto.dto

import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import java.security.KeyPair
import java.security.PrivateKey

data class UserKeysDto(
    val userId: Long,
    val identityKey: ByteArray,
    val signedPreKey: Pair<ByteArray, ByteArray>,
    val oneTimePreKeys: ByteArray
)

data class UserKeysDecodedDto(
    val userId: Long,
    val identityKey: PrivateKey,
    val signedPreKey: KeyPair,
    val oneTimePreKeys: PrivateKey
)

fun UserKeysDto.toDecodedDto() = UserKeysDecodedDto(
    userId = userId,
    identityKey = EncryptionAndDecryptionUtility().decodePrivateKey(identityKey),
    signedPreKey = KeyPair(
        EncryptionAndDecryptionUtility().decodePublicKey(signedPreKey.first),
        EncryptionAndDecryptionUtility().decodePrivateKey(signedPreKey.second)
    ),
    oneTimePreKeys = EncryptionAndDecryptionUtility().decodePrivateKey(oneTimePreKeys)
)

