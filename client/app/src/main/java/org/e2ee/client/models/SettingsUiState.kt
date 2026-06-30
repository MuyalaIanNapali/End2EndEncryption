package org.e2ee.client.models

data class SettingsUiState(
    val isBackupEnabled: Boolean = false,
    val isBackupLoading: Boolean = false,
    val backupError: String? = null,
    val backupSuccess: Boolean = false,
    val showNoAccountDialog: Boolean = false,
    val isBackupNowRunning: Boolean = false
)
