package org.e2ee.crypto

import org.e2ee.common.UserKeysDecodedDto
import org.e2ee.common.UserKeysDto
import org.e2ee.crypto.encryptDecrypt.EncryptionAndDecryptionUtility
import java.security.KeyPair

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