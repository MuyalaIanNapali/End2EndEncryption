package org.e2ee.data.local.user.share

import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.serialization.json.Json
import org.e2ee.common.Share
import org.e2ee.data.local.user.StoredRecoveryShare

class RecoveryShareStore(
    private val prefs: SharedPreferences
) {

    companion object {
        private const val KEY = "recovery_share"
    }

    fun save(share: Share) {
        val json = Json.encodeToString(
            StoredRecoveryShare(
                share = share
            )
        )

        prefs.edit {
            putString(KEY, json)
        }
    }

    fun load(): Share? {
        val json =
            prefs.getString(KEY, null)
                ?: return null

        return Json.decodeFromString<StoredRecoveryShare>(
            json
        ).share
    }

    fun clear() {
        prefs.edit {
            remove(KEY)
        }
    }
}