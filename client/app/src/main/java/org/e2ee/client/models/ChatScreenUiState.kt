package org.e2ee.client.models

data class ChatScreenUiState(
    val sessionId : String? = null,
    val messages: List<ChatMessageUi> = emptyList(),
    val isSending: Boolean = false,
    val isLoading: Boolean = false,
    val errorMessage: String? = null
)
