package org.e2ee.data.repository.backup

import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BackupPreferencesRepository @Inject constructor(
    private val prefs: SharedPreferences
) {

    companion object {
        private const val KEY_BACKUP_ENABLED = "backup_enabled"
    }

    private val _backupEnabled = MutableStateFlow(
        prefs.getBoolean(KEY_BACKUP_ENABLED, false)
    )

    val backupEnabled: StateFlow<Boolean> = _backupEnabled.asStateFlow()

    fun setBackupEnabled(enabled: Boolean) {
        prefs.edit { putBoolean(KEY_BACKUP_ENABLED, enabled) }
        _backupEnabled.value = enabled
    }

    fun isBackupEnabled(): Boolean = prefs.getBoolean(KEY_BACKUP_ENABLED, false)
}
