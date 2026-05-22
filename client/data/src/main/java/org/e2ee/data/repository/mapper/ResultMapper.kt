package org.e2ee.data.repository.mapper

import org.e2ee.data.remote.network.ApiResult
import org.e2ee.domain.model.DomainResult

fun <T> ApiResult<T>.toDomainResult(): DomainResult<T> {
    return when (this) {
        is ApiResult.Success -> DomainResult.Success(data)

        is ApiResult.Error -> DomainResult.Error(
            message = message,
            code = statusCode
        )

        is ApiResult.NetworkError -> DomainResult.NetworkError

        is ApiResult.UnknownError -> DomainResult.UnknownError(message)
    }
}