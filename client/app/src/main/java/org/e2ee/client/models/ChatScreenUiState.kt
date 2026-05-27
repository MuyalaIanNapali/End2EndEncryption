package org.e2ee.client.models

data class ChatScreenUiState(
    val messages: List<ChatMessageUi> = emptyList(),
    val isLoading: Boolean = false,
    val errorMessage: String? = null
)
