package org.e2ee.crypto.backup.encryptDecrypt

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class Decryption {

    fun decryptBackupData(
        backupKey: SecretKey,
        encryptedData: ByteArray
    ): ByteArray {

        require(encryptedData.size > 12) {
            "Invalid encrypted data"
        }

        val iv = encryptedData.copyOfRange(0, 12)

        val cipherText = encryptedData.copyOfRange(12, encryptedData.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val spec = GCMParameterSpec(128, iv)

        cipher.init(Cipher.DECRYPT_MODE, backupKey, spec)

        return cipher.doFinal(cipherText)
    }
}