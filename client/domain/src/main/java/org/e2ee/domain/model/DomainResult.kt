package org.e2ee.domain.model

sealed class DomainResult<out T> {
    data class Success<T>(val data: T) : DomainResult<T>()

    data class Error(
        val message: String,
        val code: Int? = null
    ) : DomainResult<Nothing>()

    data object NetworkError : DomainResult<Nothing>()

    data class UnknownError(
        val message: String? = null
    ) : DomainResult<Nothing>()
}