package org.e2ee.client.auth.screen

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.content.LoginScreenContent
import org.e2ee.client.auth.viewmodel.LoginViewModel

@Composable
fun LoginScreen(
    viewModel: LoginViewModel = hiltViewModel(),
    onRegisterClick: () -> Unit,
    onLoginSuccess: () -> Unit = {}
) {
    val uiState = viewModel.uiState.collectAsStateWithLifecycle().value

    LaunchedEffect(uiState.isLoginSuccessful) {
        if (uiState.isLoginSuccessful) {
            onLoginSuccess()
        }
    }

    LoginScreenContent(
        emailOrUsername = uiState.emailOrUsername,
        password = uiState.password,
        isLoading = uiState.isLoading,
        errorMessage = uiState.errorMessage,
        onEmailOrUsernameChange = viewModel::onEmailOrUsernameChange,
        onPasswordChange = viewModel::onPasswordChange,
        onLoginClick = viewModel::login
    )
}

@Preview(showBackground = true)
@Composable
fun LoginScreenPreview() {
    LoginScreenContent(
        emailOrUsername = "",
        password = "",
        isLoading = false,
        errorMessage = null,
        onEmailOrUsernameChange = {},
        onPasswordChange = {},
        onLoginClick = {}
    )
}