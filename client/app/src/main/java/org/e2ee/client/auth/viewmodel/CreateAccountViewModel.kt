package org.e2ee.client.auth.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.client.models.CreateAccountUiState
import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.model.RegistrationRequest
import org.e2ee.domain.usecase.CreateAccountUseCase
import javax.inject.Inject

@HiltViewModel
class CreateAccountViewModel @Inject constructor(
    private val createAccountUseCase: CreateAccountUseCase
) : ViewModel() {

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
                errorMessage = null,
                isAccountCreationSuccessful = false
            )

            try {
                val request = RegistrationRequest(
                    email = currentState.email.trim(),
                    username = currentState.username.trim(),
                    password = currentState.password
                )

                when (val result = createAccountUseCase(request)) {
                    is DomainResult.Success -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            isAccountCreationSuccessful = result.data,
                            errorMessage = if (result.data) {
                                null
                            } else {
                                "Account creation failed"
                            }
                        )
                    }

                    is DomainResult.Error -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            isAccountCreationSuccessful = false,
                            errorMessage = result.message
                        )
                    }

                    DomainResult.NetworkError -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            isAccountCreationSuccessful = false,
                            errorMessage = "Network error. Please check your connection."
                        )
                    }

                    is DomainResult.UnknownError -> {
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            isAccountCreationSuccessful = false,
                            errorMessage = result.message ?: "Something went wrong"
                        )
                    }
                }

            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    isAccountCreationSuccessful = false,
                    errorMessage = e.message ?: "Something went wrong"
                )
            }
        }
    }
}