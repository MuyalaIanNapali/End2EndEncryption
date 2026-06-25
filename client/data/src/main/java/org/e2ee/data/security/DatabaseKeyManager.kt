package org.e2ee.data.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Manages the SQLCipher database encryption key.
 *
 * IMPORTANT: [getOrCreateDatabaseKey] touches the Android Keystore (hardware-backed
 * crypto) and SharedPreferences. Both can block for several hundred milliseconds on
 * first call. Always invoke this from an IO coroutine dispatcher — never on the
 * main thread.
 */
@Singleton
class DatabaseKeyManager @Inject constructor(
    private val prefs: SharedPreferences,
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "e2ee_sqlcipher_master_key"
        private const val PREF_DB_KEY = "encrypted_sqlcipher_key"
        private const val PREF_DB_KEY_IV = "encrypted_sqlcipher_key_iv"
        private const val DATABASE_NAME = "client_database"
        private const val AES_MODE = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val SQLCIPHER_KEY_SIZE_BYTES = 32
    }

    // Cache the derived key in memory — subsequent calls within the same
    // process lifetime skip the Keystore round-trip entirely (~200-400ms saved).
    @Volatile
    private var cachedKey: ByteArray? = null

    fun getOrCreateDatabaseKey(): ByteArray {
        cachedKey?.let { return it }
        return deriveKey().also { cachedKey = it }
    }

    private fun deriveKey(): ByteArray {
        val encryptedKey = prefs.getString(PREF_DB_KEY, null)
        val iv = prefs.getString(PREF_DB_KEY_IV, null)

        if (encryptedKey != null && iv != null) {
            return try {
                decryptDatabaseKey(
                    encryptedData = Base64.decode(encryptedKey, Base64.NO_WRAP),
                    iv = Base64.decode(iv, Base64.NO_WRAP)
                )
            } catch (e: AEADBadTagException) {
                resetDatabaseCompletely()
                createAndStoreNewDatabaseKey()
            } catch (e: Exception) {
                resetDatabaseCompletely()
                createAndStoreNewDatabaseKey()
            }
        }

        return createAndStoreNewDatabaseKey()
    }

    fun resetDatabaseCompletely() {
        cachedKey = null
        clearStoredEncryptedDatabaseKey()
        deleteMasterKeyFromAndroidKeystore()
        deleteSqlCipherDatabaseFiles()
    }

    private fun createAndStoreNewDatabaseKey(): ByteArray {
        val newDatabaseKey = ByteArray(SQLCIPHER_KEY_SIZE_BYTES)
        SecureRandom().nextBytes(newDatabaseKey)
        val encrypted = encryptDatabaseKey(newDatabaseKey)
        prefs.edit {
            putString(PREF_DB_KEY, Base64.encodeToString(encrypted.encryptedData, Base64.NO_WRAP))
            putString(PREF_DB_KEY_IV, Base64.encodeToString(encrypted.iv, Base64.NO_WRAP))
        }
        return newDatabaseKey
    }

    private fun clearStoredEncryptedDatabaseKey() {
        prefs.edit { remove(PREF_DB_KEY); remove(PREF_DB_KEY_IV) }
    }

    private fun deleteMasterKeyFromAndroidKeystore() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {}
    }

    private fun deleteSqlCipherDatabaseFiles() {
        context.deleteDatabase(DATABASE_NAME)
        context.getDatabasePath(DATABASE_NAME).delete()
        context.getDatabasePath("$DATABASE_NAME-wal").delete()
        context.getDatabasePath("$DATABASE_NAME-shm").delete()
        context.getDatabasePath("$DATABASE_NAME-journal").delete()
    }

    private fun encryptDatabaseKey(databaseKey: ByteArray): EncryptedData {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        return EncryptedData(encryptedData = cipher.doFinal(databaseKey), iv = cipher.iv)
    }

    private fun decryptDatabaseKey(encryptedData: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), GCMParameterSpec(GCM_TAG_LENGTH, iv))
        return cipher.doFinal(encryptedData)
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return keyGenerator.generateKey()
    }

    private data class EncryptedData(val encryptedData: ByteArray, val iv: ByteArray)
}