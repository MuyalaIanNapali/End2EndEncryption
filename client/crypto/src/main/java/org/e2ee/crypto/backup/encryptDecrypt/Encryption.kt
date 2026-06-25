package org.e2ee.crypto.backup.encryptDecrypt

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

class Encryption {

    private val secureRandom = SecureRandom()

    fun encryptBackupData(
        backupKey: SecretKey,
        database: ByteArray
    ): ByteArray {

        val iv = ByteArray(12)
        secureRandom.nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val spec = GCMParameterSpec(128, iv) // 128-bit auth tag
        cipher.init(Cipher.ENCRYPT_MODE, backupKey, spec)

        val encrypted = cipher.doFinal(database)

        return iv + encrypted
    }
}