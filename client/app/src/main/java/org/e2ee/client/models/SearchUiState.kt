package org.e2ee.client.models

import org.e2ee.domain.model.RemoteUserDetails

data class SearchUiState(
    val query: String = "",
    val searchResults: List<RemoteUserDetails> = emptyList(),
    val isLoading: Boolean = false,
    val errorMessage: String? = null
)
