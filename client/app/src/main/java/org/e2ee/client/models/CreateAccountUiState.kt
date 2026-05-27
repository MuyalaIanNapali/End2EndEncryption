package org.e2ee.client.models

data class CreateAccountUiState(
    val email: String = "",
    val username: String = "",
    val password: String = "",
    val confirmPassword: String = "",
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val isAccountCreationSuccessful: Boolean = false
)
