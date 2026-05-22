package org.e2ee.data.remote.network

data class ApiErrorResponse(
    val timestamp: String? = null,
    val status: Int? = null,
    val error: String? = null,
    val message: String? = null,
    val path: String? = null
)

data class ValidationErrorResponse(
    val timestamp: String? = null,
    val status: Int? = null,
    val error: String? = null,
    val message: String? = null,
    val fieldErrors: Map<String, String>? = null
)

sealed class ApiResult<out T> {
    data class Success<T>(val data: T) : ApiResult<T>()

    data class Error(
        val statusCode: Int?,
        val message: String,
        val fieldErrors: Map<String, String>? = null
    ) : ApiResult<Nothing>()

    data class NetworkError(
        val message: String = "Please check your internet connection"
    ) : ApiResult<Nothing>()

    data class UnknownError(
        val message: String = "Something went wrong"
    ) : ApiResult<Nothing>()
}
