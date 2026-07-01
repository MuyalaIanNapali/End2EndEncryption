package org.e2ee.client.auth.viewmodel

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.usecase.RestoreBackupUseCase
import javax.inject.Inject

data class RestoreBackupUiState(
    val isRestoring: Boolean = false,
    val errorMessage: String? = null,
    val isFinished: Boolean = false   // restore succeeded OR skipped -> proceed
)

@HiltViewModel
class RestoreBackupViewModel @Inject constructor(
    private val restoreBackupUseCase: RestoreBackupUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(RestoreBackupUiState())
    val uiState: StateFlow<RestoreBackupUiState> = _uiState.asStateFlow()

    fun restore(activity: Activity) {
        if (_uiState.value.isRestoring) return
        viewModelScope.launch {
            _uiState.update { it.copy(isRestoring = true, errorMessage = null) }
            when (val result = restoreBackupUseCase(activity)) {
                is DomainResult.Success ->
                    _uiState.update { it.copy(isRestoring = false, isFinished = true) }
                is DomainResult.Error ->
                    _uiState.update { it.copy(isRestoring = false, errorMessage = result.message) }
                DomainResult.NetworkError ->
                    _uiState.update { it.copy(isRestoring = false, errorMessage = "Network error. Please check your connection.") }
                is DomainResult.UnknownError ->
                    _uiState.update { it.copy(isRestoring = false, errorMessage = result.message ?: "An unexpected error occurred") }
            }
        }
    }

    fun skip() {
        _uiState.update { it.copy(isFinished = true) }
    }

    fun clearError() {
        _uiState.update { it.copy(errorMessage = null) }
    }
}