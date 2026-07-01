package org.e2ee.data.remote.shares.dto

import org.e2ee.data.remote.util.toBase64

data class ShareResponse(
    val userId: Long,
    val share: ShareDtoResponse
)

data class ShareDtoResponse(
    val index: Int,
    val value: String
)

fun ShareDtoResponse.toShareDto(): ShareDto {
    return ShareDto(
        index = this.index,
        value = this.value.toBase64()
    )
}


