package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.e2ee.client.auth.viewmodel.SessionViewModel
import org.e2ee.client.models.SessionUiState
import org.e2ee.client.ui.elements.AppLoadingIndicator

@Composable
fun NavigationRoot(
    modifier: Modifier = Modifier,
    sessionViewModel: SessionViewModel = hiltViewModel()
) {
    val sessionState by sessionViewModel.sessionState.collectAsStateWithLifecycle()

    when (sessionState) {
        SessionUiState.Checking -> {
            AppLoadingIndicator()
        }

        SessionUiState.Unauthenticated -> {
            AuthNavigation(
                onAuthSuccess = {
                    sessionViewModel.onAuthSuccess()
                }
            )
        }

        SessionUiState.Authenticated -> {
            MainNavigation(
                onLogOut = {
                    sessionViewModel.logout()
                }
            )
        }
    }
}