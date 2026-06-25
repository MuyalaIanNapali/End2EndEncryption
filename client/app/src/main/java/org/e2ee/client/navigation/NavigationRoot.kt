package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.viewmodel.SessionViewModel
import org.e2ee.client.models.SessionUiState
import org.e2ee.client.splash.AppSplashScreen

@Composable
fun NavigationRoot(
    modifier: Modifier = Modifier,
    sessionViewModel: SessionViewModel = hiltViewModel()
) {
    val sessionState by sessionViewModel.sessionState.collectAsStateWithLifecycle()

    when (sessionState) {
        SessionUiState.Checking -> {
            // Branded splash while auto-login runs — no spinner visible to user
            AppSplashScreen(modifier = modifier)
        }

        SessionUiState.Unauthenticated -> {
            AuthNavigation(
                modifier = modifier,
                onAuthSuccess = {
                    sessionViewModel.onAuthSuccess()
                }
            )
        }

        SessionUiState.Authenticated -> {
            MainNavigation(
                modifier = modifier,
                onLogOut = {
                    sessionViewModel.logout()
                }
            )
        }
    }
}
