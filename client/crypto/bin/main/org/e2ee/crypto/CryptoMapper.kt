package org.e2ee.crypto

import org.e2ee.common.UserKeysDecodedDecDto
import org.e2ee.common.UserKeysDecodedEncDto
import org.e2ee.common.UserKeysDto
import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import java.security.KeyPair

fun UserKeysDto.toDecodedEncDto(): UserKeysDecodedEncDto {
    val crypto = EncryptionAndDecryptionUtility()

    println("Decoding UserKeysDto: $this")
    return UserKeysDecodedEncDto(
        userId = userId,
        identityKey = crypto.decodePrivateKey(identityKey),
        signedPreKey = KeyPair(
            crypto.decodePublicKey(signedPreKey.first),
            crypto.decodePrivateKey(signedPreKey.second)
        ),
        oneTimePreKeys = oneTimePreKeys?.let {
            crypto.decodePublicKey(it)
        }
    )
}

fun UserKeysDto.toDecodedDecDto(): UserKeysDecodedDecDto {
    val crypto = EncryptionAndDecryptionUtility()

    println("Decoding UserKeysDto: $this")
    return UserKeysDecodedDecDto(
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