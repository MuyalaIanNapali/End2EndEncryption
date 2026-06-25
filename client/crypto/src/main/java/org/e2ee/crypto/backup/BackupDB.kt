package org.e2ee.crypto.backup

import org.e2ee.crypto.backup.encryptDecrypt.BackupKey
import org.e2ee.crypto.backup.encryptDecrypt.Decryption
import org.e2ee.crypto.backup.encryptDecrypt.Encryption
import org.e2ee.crypto.backup.shamirSecretSharing.GenerateShares
import org.e2ee.crypto.backup.shamirSecretSharing.RecoverSecret
import org.e2ee.common.Share
import javax.crypto.spec.SecretKeySpec

class BackupDB {
    fun encryptDatabaseBackup(database: ByteArray): Pair<ByteArray, List<Share>> {
        val key = BackupKey().generateBackupKey()

        val encryptedDatabase = Encryption().encryptBackupData(key, database)

        val shares = GenerateShares().makeRandomShares(
            key.encoded,
            minimum = 3,
            shares = 5
        )

        return Pair(encryptedDatabase, shares)
    }

    fun decryptDatabaseBackup(encryptedDatabase: ByteArray, shares: List<Share>): ByteArray {
        val keyBytes = RecoverSecret().recoverSecret(shares)
        val key = SecretKeySpec(keyBytes, "AES")

        return Decryption().decryptBackupData(key, encryptedDatabase)
    }
}