package org.e2ee.data.remote.auth

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
        prefs.edit { putString(ACCESS_TOKEN, token) }
    }

    fun saveRefreshToken(token: String) {
        prefs.edit { putString(REFRESH_TOKEN, token) }
    }

    fun getAccessToken(): String? {
        return prefs.getString(ACCESS_TOKEN, null)
    }

    fun getRefreshToken(): String? {
        return prefs.getString(REFRESH_TOKEN, null)
    }

    fun clearTokens() {
        prefs.edit {
            remove(ACCESS_TOKEN)
                .remove(REFRESH_TOKEN)
        }

    }

    fun saveTokens(accessToken: String, refreshToken: String) {
        prefs.edit {
            putString(ACCESS_TOKEN, accessToken)
            putString(REFRESH_TOKEN, refreshToken)
        }
    }
}