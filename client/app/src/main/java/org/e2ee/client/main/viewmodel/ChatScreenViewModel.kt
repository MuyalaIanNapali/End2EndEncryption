package org.e2ee.client.main.viewmodel

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.e2ee.client.models.ChatMessageUi
import org.e2ee.client.models.ChatScreenUiState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class ChatScreenViewModel @Inject constructor() : ViewModel() {

    private val _uiState = MutableStateFlow(ChatScreenUiState())
    val uiState: StateFlow<ChatScreenUiState> = _uiState.asStateFlow()

    suspend fun loadMessages(sessionId: String) {
        _uiState.value = _uiState.value.copy(isLoading = true)

        //delay
        delay(1600)

        _uiState.value = ChatScreenUiState(
            isLoading = false,
            messages = listOf(
                ChatMessageUi(
                    id = "1",
                    sessionId = sessionId,
                    text = "Hey, how are you?",
                    timestamp = "10:30 AM",
                    isSentByUser = false
                ),
                ChatMessageUi(
                    id = "2",
                    sessionId = sessionId,
                    text = "I'm good, thanks! How about you?",
                    timestamp = "10:32 AM",
                    isSentByUser = true
                ),
                ChatMessageUi(
                    id = "3",
                    sessionId = sessionId,
                    text = "Doing well! Just wanted to check in.",
                    timestamp = "10:35 AM",
                    isSentByUser = false
                )
            )
        )
    }

    fun sendMessage(sessionId: String, messageText: String) {
        val trimmedMessage = messageText.trim()

        if (trimmedMessage.isBlank()) return

        val newMessage = ChatMessageUi(
            id = System.currentTimeMillis().toString(),
            sessionId = sessionId,
            text = trimmedMessage,
            timestamp = getCurrentTime(),
            isSentByUser = true
        )

        _uiState.value = _uiState.value.copy(
            messages = _uiState.value.messages + newMessage
        )
    }

    private fun getCurrentTime(): String {
        return SimpleDateFormat("hh:mm a", Locale.getDefault()).format(Date())
    }
}