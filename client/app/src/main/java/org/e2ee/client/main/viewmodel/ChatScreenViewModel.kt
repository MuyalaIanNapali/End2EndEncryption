package org.e2ee.client.main.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.launch
import org.e2ee.client.models.ChatScreenUiState
import org.e2ee.client.models.toChatMessageUi
import org.e2ee.domain.model.RemoteUserDetails
import org.e2ee.domain.usecase.ObserveMessagesUseCase
import org.e2ee.domain.usecase.SendMessageUseCase
import javax.inject.Inject

@HiltViewModel
class ChatScreenViewModel @Inject constructor(
    private val observeMessagesUseCase: ObserveMessagesUseCase,
    private val sendMessageUseCase: SendMessageUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(ChatScreenUiState())
    val uiState: StateFlow<ChatScreenUiState> = _uiState.asStateFlow()

    private var observeMessagesJob: Job? = null

    fun loadMessages(sessionId: String?) {
        _uiState.value = _uiState.value.copy(
            sessionId = sessionId,
            isLoading = false,
            errorMessage = null
        )

        if (sessionId == null) {
            return
        }

        observeChatMessages(sessionId)
    }

    private fun observeChatMessages(sessionId: String) {
        observeMessagesJob?.cancel()

        observeMessagesJob = viewModelScope.launch {
            observeMessagesUseCase(sessionId)
                .catch { error ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        errorMessage = error.message ?: "Failed to load messages"
                    )
                }
                .collect { messages ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        messages = messages.map { it.toChatMessageUi() },
                        errorMessage = null
                    )
                }
        }
    }

    fun sendMessage(
        receiverId: String,
        username: String,
        email: String,
        messageText: String
    ) {
        val trimmedMessage = messageText.trim()
        if (trimmedMessage.isBlank()) return

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isSending = true,
                errorMessage = null
            )

            try {
                val newSessionId = sendMessageUseCase(
                    details = RemoteUserDetails(
                        id = receiverId.toLong(),
                        username = username,
                        email = email
                    ),
                    content = trimmedMessage
                )

                val previousSessionId = _uiState.value.sessionId

                _uiState.value = _uiState.value.copy(
                    sessionId = newSessionId,
                    isSending = false
                )

                if (previousSessionId == null || previousSessionId != newSessionId) {
                    observeChatMessages(newSessionId)
                }

            } catch (error: Exception) {
                _uiState.value = _uiState.value.copy(
                    isSending = false,
                    errorMessage = error.message ?: "Failed to send message"
                )
            }
        }
    }
}