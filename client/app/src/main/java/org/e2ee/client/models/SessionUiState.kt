package org.e2ee.client.models

sealed interface SessionUiState {
    data object Checking : SessionUiState
    data object Authenticated : SessionUiState
    data object Unauthenticated : SessionUiState
}