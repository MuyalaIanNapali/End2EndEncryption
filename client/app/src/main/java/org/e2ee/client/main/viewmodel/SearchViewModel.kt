package org.e2ee.client.main.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.client.models.SearchUiState
import org.e2ee.domain.model.DomainResult
import org.e2ee.domain.usecase.SearchUsersByUsernameUseCase
import javax.inject.Inject

@HiltViewModel
class SearchViewModel @Inject constructor(
    private val searchUsersByUsernameUseCase: SearchUsersByUsernameUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(SearchUiState())
    val uiState: StateFlow<SearchUiState> = _uiState.asStateFlow()

    private var searchJob: Job? = null

    fun onQueryChange(query: String) {
        _uiState.value = _uiState.value.copy(
            query = query,
            errorMessage = null
        )

        searchJob?.cancel()

        if (query.isBlank()) {
            _uiState.value = _uiState.value.copy(
                searchResults = emptyList(),
                isLoading = false,
                errorMessage = null
            )
            return
        }

        searchJob = viewModelScope.launch {
            delay(400) // debounce so it doesn't call API on every single letter instantly
            performSearch(query.trim())
        }
    }

    private suspend fun performSearch(query: String) {
        _uiState.value = _uiState.value.copy(
            isLoading = true,
            errorMessage = null
        )
        Log.d("search", "Performing search for query: $query")

        when (val result = searchUsersByUsernameUseCase(query)) {
            is DomainResult.Success -> {
                _uiState.value = _uiState.value.copy(
                    searchResults = result.data,
                    isLoading = false,
                    errorMessage = null
                )
            }

            is DomainResult.Error -> {
                _uiState.value = _uiState.value.copy(
                    searchResults = emptyList(),
                    errorMessage = result.message,
                    isLoading = false
                )
            }

            DomainResult.NetworkError -> {
                _uiState.value = _uiState.value.copy(
                    searchResults = emptyList(),
                    errorMessage = "Network error. Please check your connection.",
                    isLoading = false
                )
            }

            is DomainResult.UnknownError -> {
                _uiState.value = _uiState.value.copy(
                    searchResults = emptyList(),
                    errorMessage = "An unknown error occurred. Please try again later.",
                    isLoading = false
                )
            }
        }
    }
}