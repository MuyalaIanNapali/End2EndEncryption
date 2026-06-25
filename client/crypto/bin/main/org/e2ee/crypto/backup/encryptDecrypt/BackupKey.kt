package org.e2ee.crypto.backup.encryptDecrypt

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class BackupKey {

    fun generateBackupKey(): SecretKey {

        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)

        return keyGenerator.generateKey()
    }
}