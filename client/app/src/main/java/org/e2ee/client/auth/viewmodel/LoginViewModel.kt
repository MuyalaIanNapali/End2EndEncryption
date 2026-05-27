package org.e2ee.client.auth.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.client.models.LoginUiState
import javax.inject.Inject

@HiltViewModel
class LoginViewModel @Inject constructor() : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    fun onEmailOrUsernameChange(value: String) {
        _uiState.value = _uiState.value.copy(
            emailOrUsername = value,
            errorMessage = null
        )
    }

    fun onPasswordChange(value: String) {
        _uiState.value = _uiState.value.copy(
            password = value,
            errorMessage = null
        )
    }

    fun login() {
        val currentState = _uiState.value

        if (currentState.emailOrUsername.isBlank()) {
            _uiState.value = currentState.copy(
                errorMessage = "Email or username is required"
            )
            return
        }

        if (currentState.password.isBlank()) {
            _uiState.value = currentState.copy(
                errorMessage = "Password is required"
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = currentState.copy(
                isLoading = true,
                errorMessage = null
            )

            // Temporary fake delay until backend login is connected
            delay(800)

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                isLoginSuccessful = true
            )
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(errorMessage = null)
    }
}