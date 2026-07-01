package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.screen.RestoreBackupScreen
import org.e2ee.client.auth.viewmodel.SessionViewModel
import org.e2ee.client.models.SessionUiState
import org.e2ee.client.splash.AppSplashScreen

@Composable
fun NavigationRoot(
    modifier: Modifier = Modifier,
    sessionViewModel: SessionViewModel = hiltViewModel()
) {
    val sessionState by sessionViewModel.sessionState.collectAsStateWithLifecycle()
    var pendingRestoreChoice by rememberSaveable { mutableStateOf(false) }

    when (sessionState) {
        SessionUiState.Checking -> AppSplashScreen(modifier = modifier)

        SessionUiState.Unauthenticated -> {
            if (pendingRestoreChoice) {
                RestoreBackupScreen(
                    modifier = modifier,
                    onFinished = {
                        pendingRestoreChoice = false
                        sessionViewModel.onAuthSuccess()
                    }
                )
            } else {
                AuthNavigation(
                    modifier = modifier,
                    onLoginSuccess = { pendingRestoreChoice = true },
                    onRegisterSuccess = { sessionViewModel.onAuthSuccess() }
                )
            }
        }

        SessionUiState.Authenticated -> {
            MainNavigation(modifier = modifier, onLogOut = { sessionViewModel.logout() })
        }
    }
}