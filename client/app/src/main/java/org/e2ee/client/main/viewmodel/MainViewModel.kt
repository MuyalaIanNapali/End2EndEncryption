package org.e2ee.client.main.viewmodel

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import org.e2ee.domain.usecase.ConnectWebSocketUseCase
import org.e2ee.domain.usecase.DisconnectWebSocketUseCase
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val connectWebSocketUseCase: ConnectWebSocketUseCase,
    private val disconnectWebSocketUseCase: DisconnectWebSocketUseCase
) : ViewModel() {

    private var connected = false

    fun connectWebSocket() {
        if (!connected) {
            connectWebSocketUseCase()
            connected = true
        }
    }

    fun disconnectWebSocket() {
        if (connected) {
            disconnectWebSocketUseCase()
            connected = false
        }
    }

    override fun onCleared() {
        disconnectWebSocket()
        super.onCleared()
    }
}