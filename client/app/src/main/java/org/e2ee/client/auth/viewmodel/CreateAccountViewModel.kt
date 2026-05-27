package org.e2ee.client.auth.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.client.models.CreateAccountUiState
import javax.inject.Inject

@HiltViewModel
class CreateAccountViewModel @Inject constructor() : ViewModel() {

    private val _uiState = MutableStateFlow(CreateAccountUiState())
    val uiState: StateFlow<CreateAccountUiState> = _uiState.asStateFlow()

    fun onEmailChange(value: String) {
        _uiState.value = _uiState.value.copy(
            email = value,
            errorMessage = null
        )
    }

    fun onUsernameChange(value: String) {
        _uiState.value = _uiState.value.copy(
            username = value,
            errorMessage = null
        )
    }

    fun onPasswordChange(value: String) {
        _uiState.value = _uiState.value.copy(
            password = value,
            errorMessage = null
        )
    }

    fun onConfirmPasswordChange(value: String) {
        _uiState.value = _uiState.value.copy(
            confirmPassword = value,
            errorMessage = null
        )
    }

    fun createAccount() {
        val currentState = _uiState.value

        if (currentState.email.isBlank()) {
            _uiState.value = currentState.copy(
                errorMessage = "Email is required"
            )
            return
        }

        if (currentState.username.isBlank()) {
            _uiState.value = currentState.copy(
                errorMessage = "Username is required"
            )
            return
        }

        if (currentState.password.isBlank()) {
            _uiState.value = currentState.copy(
                errorMessage = "Password is required"
            )
            return
        }

        if (currentState.confirmPassword.isBlank()) {
            _uiState.value = currentState.copy(
                errorMessage = "Confirm password is required"
            )
            return
        }

        if (currentState.password != currentState.confirmPassword) {
            _uiState.value = currentState.copy(
                errorMessage = "Passwords do not match"
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = currentState.copy(
                isLoading = true,
                errorMessage = null
            )

            // Temporary until you connect your register use case/API
            delay(800)

            _uiState.value = _uiState.value.copy(
                isLoading = false,
                isAccountCreationSuccessful = true
            )
        }
    }
}