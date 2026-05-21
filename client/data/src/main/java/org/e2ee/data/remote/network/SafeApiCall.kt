package org.e2ee.data.remote.network

import com.google.gson.Gson
import retrofit2.Response
import java.io.IOException

suspend fun <T> safeApiCall(
    apiCall: suspend () -> Response<T>
): ApiResult<T> {
    return try {
        val response = apiCall()

        if (response.isSuccessful) {
            val body = response.body()

            return if (body != null) {
                ApiResult.Success(body)
            } else if (response.code() == 204) {
                @Suppress("UNCHECKED_CAST")
                ApiResult.Success(Unit as T)
            } else {
                ApiResult.UnknownError("Empty response from server")
            }
        } else {
            val errorBody = response.errorBody()?.string()

            val apiError = try {
                Gson().fromJson(errorBody, ApiErrorResponse::class.java)
            } catch (e: Exception) {
                null
            }

            val validationError = try {
                Gson().fromJson(errorBody, ValidationErrorResponse::class.java)
            } catch (e: Exception) {
                null
            }

            ApiResult.Error(
                statusCode = response.code(),
                message = apiError?.message
                    ?: validationError?.message
                    ?: defaultMessageForCode(response.code()),
                fieldErrors = validationError?.fieldErrors
            )
        }
    } catch (e: IOException) {
        ApiResult.NetworkError()
    } catch (e: Exception) {
        ApiResult.UnknownError(e.message ?: "Something went wrong")
    }
}

private fun defaultMessageForCode(code: Int): String {
    return when (code) {
        400 -> "Invalid request"
        401 -> "Please login again"
        403 -> "You do not have permission"
        404 -> "Resource not found"
        409 -> "This value already exists"
        500 -> "Server error. Please try again later"
        else -> "Something went wrong"
    }
}