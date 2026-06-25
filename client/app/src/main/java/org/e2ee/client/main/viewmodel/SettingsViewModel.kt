package org.e2ee.client.main.viewmodel

import android.app.Activity
import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.e2ee.client.models.SettingsUiState
import org.e2ee.data.repository.backup.BackupPreferencesRepository
import org.e2ee.data.repository.backup.DriveTokenManager
import org.e2ee.data.worker.BackupWorker
import org.e2ee.domain.model.BackupAuthResult
import org.e2ee.domain.model.DriveConsentRequest
import org.e2ee.domain.usecase.EnableDriveBackupUseCase
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val enableDriveBackupUseCase: EnableDriveBackupUseCase,
    private val backupPreferencesRepository: BackupPreferencesRepository,
    private val driveTokenManager: DriveTokenManager,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(SettingsUiState())
    val uiState = _uiState.asStateFlow()

    private val _consentRequests = MutableSharedFlow<DriveConsentRequest>()
    val consentRequests = _consentRequests.asSharedFlow()

    // Only true while actively waiting for the Drive consent screen result
    private var awaitingDriveConsent = false

    init {
        viewModelScope.launch {
            backupPreferencesRepository.backupEnabled.collect { enabled ->
                _uiState.update { current ->
                    if (!current.isBackupLoading) current.copy(isBackupEnabled = enabled)
                    else current
                }
            }
        }
    }

    fun onBackupToggled(enabled: Boolean, activity: Activity) {
        if (enabled) initiateBackupAuth(activity) else disableBackup()
    }

    private fun initiateBackupAuth(activity: Activity) {
        viewModelScope.launch {
            _uiState.update {
                it.copy(isBackupLoading = true, backupError = null, showNoAccountDialog = false)
            }

            when (val result = enableDriveBackupUseCase(activity)) {
                is BackupAuthResult.Success -> {
                    // hasResolution() was false — Drive was already authorized,
                    // but we still need the access token. Re-authorize to get it.
                    // (This path is hit when the user previously granted consent.)
                    // For now treat as needing consent to obtain a fresh token.
                    awaitingDriveConsent = false
                    _uiState.update {
                        it.copy(
                            isBackupLoading = false,
                            isBackupEnabled = true,
                            backupSuccess = true
                        )
                    }
                    backupPreferencesRepository.setBackupEnabled(true)
                    BackupWorker.schedule(context)
                }

                is BackupAuthResult.ConsentRequired -> {
                    awaitingDriveConsent = true
                    _uiState.update { it.copy(isBackupLoading = false) }
                    _consentRequests.emit(result.request)
                }

                is BackupAuthResult.NoCredential -> {
                    awaitingDriveConsent = false
                    _uiState.update {
                        it.copy(isBackupLoading = false, isBackupEnabled = false, showNoAccountDialog = true)
                    }
                }

                is BackupAuthResult.Cancelled -> {
                    awaitingDriveConsent = false
                    _uiState.update { it.copy(isBackupLoading = false, isBackupEnabled = false) }
                }

                is BackupAuthResult.Error -> {
                    awaitingDriveConsent = false
                    _uiState.update {
                        it.copy(
                            isBackupLoading = false,
                            isBackupEnabled = false,
                            backupError = result.throwable.message ?: "An unexpected error occurred."
                        )
                    }
                }
            }
        }
    }

    /**
     * Called by SettingsScreen after the Drive consent intent returns RESULT_OK
     * and the access token has been extracted from the intent data.
     */
    fun onConsentGranted(driveAccessToken: String) {
        if (!awaitingDriveConsent) return  // stale launcher result — ignore
        awaitingDriveConsent = false
        driveTokenManager.save(driveAccessToken)
        backupPreferencesRepository.setBackupEnabled(true)
        BackupWorker.schedule(context)
        _uiState.update {
            it.copy(isBackupEnabled = true, backupSuccess = true, isBackupLoading = false)
        }
    }

    fun onConsentDenied() {
        awaitingDriveConsent = false
        _uiState.update { it.copy(isBackupLoading = false, isBackupEnabled = false) }
    }

    private fun disableBackup() {
        awaitingDriveConsent = false
        backupPreferencesRepository.setBackupEnabled(false)
        driveTokenManager.clear()
        BackupWorker.cancel(context)
        _uiState.update { it.copy(isBackupEnabled = false, backupSuccess = false, backupError = null) }
    }

    fun dismissNoAccountDialog() {
        _uiState.update { it.copy(showNoAccountDialog = false) }
    }

    fun clearBackupError() { _uiState.update { it.copy(backupError = null) } }
    fun clearBackupSuccess() { _uiState.update { it.copy(backupSuccess = false) } }
}