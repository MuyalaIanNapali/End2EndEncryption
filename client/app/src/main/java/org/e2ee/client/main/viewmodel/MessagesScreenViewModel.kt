package org.e2ee.client.main.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.launch
import org.e2ee.client.models.ChatPreviewCard
import org.e2ee.client.models.MessagesScreenUiState
import org.e2ee.domain.usecase.LoadChatRoomsUseCase
import org.e2ee.domain.usecase.MarkChatsAsReadUseCase
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class MessagesScreenViewModel @Inject constructor(
    private val loadChatRoomsUseCase: LoadChatRoomsUseCase,
    private val markChatsAsReadUseCase: MarkChatsAsReadUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(MessagesScreenUiState())
    val uiState: StateFlow<MessagesScreenUiState> = _uiState.asStateFlow()

    init {
        loadChatPreviews()
    }

    fun loadChatPreviews() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isLoading = true,
                errorMessage = null
            )

            loadChatRoomsUseCase()
                .catch { error ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        errorMessage = error.message ?: "Failed to load chats"
                    )
                }
                .collect { chatRooms ->
                    val chatCards = chatRooms.map { room ->
                        ChatPreviewCard(
                            sessionId = room.sessionId,
                            contactName = room.otherUsername,
                            contactEmail = room.otherUserEmail,
                            contactId = room.otherUserId,
                            lastMessage = room.lastMessage,
                            timestamp = formatTimestamp(room.lastMessageTimestamp),
                            unreadMessageCount = room.unreadMessageCount
                        )
                    }

                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        chatCards = chatCards,
                        errorMessage = null
                    )
                }
        }
    }

    fun markChatAsRead(sessionId: String) {
        viewModelScope.launch {
            try {
                markChatsAsReadUseCase(sessionId)

                _uiState.value = _uiState.value.copy(
                    chatCards = _uiState.value.chatCards.map { chat ->
                        if (chat.sessionId == sessionId) {
                            chat.copy(unreadMessageCount = 0)
                        } else {
                            chat
                        }
                    }
                )
            } catch (error: Exception) {
                _uiState.value = _uiState.value.copy(
                    errorMessage = error.message ?: "Failed to mark chat as read"
                )
            }
        }
    }

    private fun formatTimestamp(timestamp: Long?): String {
        if (timestamp == null || timestamp == 0L) return ""

        val now = System.currentTimeMillis()
        val oneDayMillis = 24 * 60 * 60 * 1000L

        return if (now - timestamp < oneDayMillis) {
            SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(timestamp))
        } else {
            SimpleDateFormat("MMM dd", Locale.getDefault()).format(Date(timestamp))
        }
    }
}