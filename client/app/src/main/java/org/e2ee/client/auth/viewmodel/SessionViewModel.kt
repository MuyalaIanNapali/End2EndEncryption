package org.e2ee.client.auth.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.client.models.SessionUiState
import org.e2ee.data.repository.auth.SessionRepository
import javax.inject.Inject

@HiltViewModel
class SessionViewModel @Inject constructor(
    private val sessionRepository: SessionRepository
) : ViewModel() {

    private val _sessionState =
        MutableStateFlow<SessionUiState>(SessionUiState.Checking)

    val sessionState: StateFlow<SessionUiState> =
        _sessionState.asStateFlow()

    init {
        checkSession()
    }

    fun checkSession() {
        Log.d("SessionViewModel", "Checking session...")
        viewModelScope.launch {
            _sessionState.value = SessionUiState.Checking
            Log.d("SessionViewModel", "Attempting auto-login...")

            val loggedIn = sessionRepository.autoLogin()

            Log.d("SessionViewModel", "Auto-login result: $loggedIn")

            _sessionState.value =
                if (loggedIn) {
                    SessionUiState.Authenticated
                } else {
                    SessionUiState.Unauthenticated
                }
        }
    }

    fun logout() {
        sessionRepository.logout()
        _sessionState.value = SessionUiState.Unauthenticated
    }

    fun onAuthSuccess() {
        _sessionState.value = SessionUiState.Authenticated
    }
}