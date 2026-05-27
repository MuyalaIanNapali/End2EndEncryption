package org.e2ee.client.auth.screen

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.content.CreateAccountScreenContent
import org.e2ee.client.auth.viewmodel.CreateAccountViewModel
import org.e2ee.client.ui.elements.AppLoadingIndicator

@Composable
fun CreateAccountScreen(
    viewModel: CreateAccountViewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
    onCreateAccountSuccess: () -> Unit = {}
) {
    val uiState = viewModel.uiState.collectAsStateWithLifecycle().value

    LaunchedEffect(uiState.isAccountCreationSuccessful) {
        if (uiState.isAccountCreationSuccessful) {
            onCreateAccountSuccess()
        }
    }

    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        CreateAccountScreenContent(
            email = uiState.email,
            username = uiState.username,
            password = uiState.password,
            confirmPassword = uiState.confirmPassword,
            isLoading = uiState.isLoading,
            errorMessage = uiState.errorMessage,
            onEmailChange = viewModel::onEmailChange,
            onUsernameChange = viewModel::onUsernameChange,
            onPasswordChange = viewModel::onPasswordChange,
            onConfirmPasswordChange = viewModel::onConfirmPasswordChange,
            onCreateAccountClick = viewModel::createAccount
        )

        if (uiState.isLoading) {
            AppLoadingIndicator()
        }
    }


}

@Composable
@Preview
fun RegisterScreenPreview() {
        CreateAccountScreen(
            onCreateAccountSuccess = {}
        )
}