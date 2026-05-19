package org.e2ee.data.local.remote.auth

import android.content.SharedPreferences
import androidx.core.content.edit

class TokenManager(
    private val prefs : SharedPreferences
) {
    companion object {
        private const val ACCESS_TOKEN = "access_token"
        private const val REFRESH_TOKEN = "refresh_token"
    }

    fun saveAccessToken(token: String) {
        prefs.edit { putString(_root_ide_package_.org.e2ee.data.local.remote.auth.TokenManager.Companion.ACCESS_TOKEN, token) }
    }

    fun saveRefreshToken(token: String) {
        prefs.edit { putString(_root_ide_package_.org.e2ee.data.local.remote.auth.TokenManager.Companion.REFRESH_TOKEN, token) }
    }

    fun getAccessToken(): String? {
        return prefs.getString(_root_ide_package_.org.e2ee.data.local.remote.auth.TokenManager.Companion.ACCESS_TOKEN, null)
    }

    fun getRefreshToken(): String? {
        return prefs.getString(_root_ide_package_.org.e2ee.data.local.remote.auth.TokenManager.Companion.REFRESH_TOKEN, null)
    }

    fun clearTokens() {
        prefs.edit {
            remove(_root_ide_package_.org.e2ee.data.local.remote.auth.TokenManager.Companion.ACCESS_TOKEN)
                .remove(_root_ide_package_.org.e2ee.data.local.remote.auth.TokenManager.Companion.REFRESH_TOKEN)
        }

    }
}