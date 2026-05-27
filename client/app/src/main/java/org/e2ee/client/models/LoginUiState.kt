package org.e2ee.client.models

data class LoginUiState(
    val emailOrUsername: String = "",
    val password: String = "",
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val isLoginSuccessful: Boolean = false
)
