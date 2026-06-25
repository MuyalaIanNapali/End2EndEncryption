package org.e2ee.data.repository.backup

import android.content.SharedPreferences
import androidx.core.content.edit
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DriveTokenManager @Inject constructor(
    private val prefs: SharedPreferences
) {
    companion object {
        private const val KEY_DRIVE_ACCESS_TOKEN = "drive_access_token"
    }

    fun save(token: String) {
        prefs.edit { putString(KEY_DRIVE_ACCESS_TOKEN, token) }
    }

    fun get(): String? = prefs.getString(KEY_DRIVE_ACCESS_TOKEN, null)

    fun clear() {
        prefs.edit { remove(KEY_DRIVE_ACCESS_TOKEN) }
    }
}