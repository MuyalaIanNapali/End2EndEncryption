package org.e2ee.client.main.viewmodel

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.e2ee.client.models.ChatPreviewCard
import org.e2ee.client.models.MessagesScreenUiState
import javax.inject.Inject

@HiltViewModel
class MessagesScreenViewModel @Inject constructor() : ViewModel() {

    private val _uiState = MutableStateFlow(MessagesScreenUiState())
    val uiState: StateFlow<MessagesScreenUiState> = _uiState.asStateFlow()

    fun loadChatPreviews() {
        _uiState.value = MessagesScreenUiState(
            chatCards = listOf(
                ChatPreviewCard(
                    sessionId = "1",
                    contactName = "Alice",
                    lastMessage = "Hey, how are you?",
                    timestamp = "10:30 AM",
                    unreadMessageCount = 2
                ),
                ChatPreviewCard(
                    sessionId = "2",
                    contactName = "Bob",
                    lastMessage = "Are we still on for tonight?",
                    timestamp = "9:15 AM",
                    unreadMessageCount = 0
                ),
                ChatPreviewCard(
                    sessionId = "3",
                    contactName = "Charlie",
                    lastMessage = "Don't forget the meeting tomorrow.",
                    timestamp = "Yesterday",
                    unreadMessageCount = 4
                )
            )
        )
    }
    fun markChatAsRead(sessionId: String) {
        _uiState.value = _uiState.value.copy(
            chatCards = _uiState.value.chatCards.map { chat ->
                if (chat.sessionId == sessionId) {
                    chat.copy(unreadMessageCount = 0)
                } else {
                    chat
                }
            }
        )
    }
}