package org.e2ee.data.security

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DatabaseKeyManager @Inject constructor(
    private val prefs: SharedPreferences
) {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "e2ee_sqlcipher_master_key"

        private const val PREF_DB_KEY = "encrypted_sqlcipher_key"
        private const val PREF_DB_KEY_IV = "encrypted_sqlcipher_key_iv"

        private const val AES_MODE = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val SQLCIPHER_KEY_SIZE_BYTES = 32
    }

    fun getOrCreateDatabaseKey(): ByteArray {
        val encryptedKey = prefs.getString(PREF_DB_KEY, null)
        val iv = prefs.getString(PREF_DB_KEY_IV, null)

        return if (encryptedKey != null && iv != null) {
            decryptDatabaseKey(
                encryptedData = Base64.decode(encryptedKey, Base64.NO_WRAP),
                iv = Base64.decode(iv, Base64.NO_WRAP)
            )
        } else {
            val newDatabaseKey = ByteArray(SQLCIPHER_KEY_SIZE_BYTES)
            SecureRandom().nextBytes(newDatabaseKey)

            val encrypted = encryptDatabaseKey(newDatabaseKey)

            prefs.edit()
                .putString(PREF_DB_KEY, Base64.encodeToString(encrypted.encryptedData, Base64.NO_WRAP))
                .putString(PREF_DB_KEY_IV, Base64.encodeToString(encrypted.iv, Base64.NO_WRAP))
                .apply()

            newDatabaseKey
        }
    }

    private fun encryptDatabaseKey(databaseKey: ByteArray): EncryptedData {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())

        return EncryptedData(
            encryptedData = cipher.doFinal(databaseKey),
            iv = cipher.iv
        )
    }

    private fun decryptDatabaseKey(
        encryptedData: ByteArray,
        iv: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), spec)

        return cipher.doFinal(encryptedData)
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        val existingKey = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existingKey != null) return existingKey

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keySpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(keySpec)
        return keyGenerator.generateKey()
    }

    private data class EncryptedData(
        val encryptedData: ByteArray,
        val iv: ByteArray
    )
}