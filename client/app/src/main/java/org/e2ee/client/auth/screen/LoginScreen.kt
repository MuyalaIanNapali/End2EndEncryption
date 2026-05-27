package org.e2ee.client.auth.screen

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.content.LoginScreenContent
import org.e2ee.client.auth.viewmodel.LoginViewModel
import org.e2ee.client.ui.elements.AppLoadingIndicator

@Composable
fun LoginScreen(
    viewModel: LoginViewModel = hiltViewModel(),
    onLoginSuccess: () -> Unit = {}
) {
    val uiState = viewModel.uiState.collectAsStateWithLifecycle().value

    LaunchedEffect(uiState.isLoginSuccessful) {
        if (uiState.isLoginSuccessful) {
            onLoginSuccess()
        }
    }

    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        LoginScreenContent(
            emailOrUsername = uiState.emailOrUsername,
            password = uiState.password,
            isLoading = uiState.isLoading,
            errorMessage = uiState.errorMessage,
            onEmailOrUsernameChange = viewModel::onEmailOrUsernameChange,
            onPasswordChange = viewModel::onPasswordChange,
            onLoginClick = viewModel::login
        )

        if (uiState.isLoading) {
            AppLoadingIndicator()
        }
    }
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