package org.e2ee.client.models

data class MessagesScreenUiState(
    val chatCards: List<ChatPreviewCard> = emptyList(),
    val isLoading: Boolean = false,
    val errorMessage: String? = null
)
