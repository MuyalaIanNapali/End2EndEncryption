package org.e2ee.client.main.viewmodel

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.data.repository.backup.BackupPreferencesRepository
import org.e2ee.domain.model.BackupAuthResult
import org.e2ee.domain.model.DriveConsentRequest
import org.e2ee.domain.usecase.EnableDriveBackupUseCase
import javax.inject.Inject

@HiltViewModel
class BackupViewModel @Inject constructor(
    private val enableDriveBackupUseCase: EnableDriveBackupUseCase,
    private val backupPreferencesRepository: BackupPreferencesRepository
) : ViewModel() {

    private val _consentRequests =
        MutableSharedFlow<DriveConsentRequest>()

    val consentRequests =
        _consentRequests.asSharedFlow()

    private val _authState =
        MutableStateFlow<BackupAuthResult?>(null)

    val authState =
        _authState.asStateFlow()

    /**
     * Reflects whether the user has backup enabled in their preferences.
     * This is the source of truth for scheduling and worker checks.
     */
    val isBackupEnabled = backupPreferencesRepository.backupEnabled

    fun enableBackup(
        activity: Activity
    ) {
        viewModelScope.launch {

            when (
                val result =
                    enableDriveBackupUseCase(activity)
            ) {

                is BackupAuthResult.ConsentRequired -> {

                    _consentRequests.emit(
                        result.request
                    )
                }

                is BackupAuthResult.Success -> {
                    backupPreferencesRepository.setBackupEnabled(true)
                    _authState.value = result
                }

                else -> {

                    _authState.value = result
                }
            }
        }
    }
}