package org.e2ee.data.remote.shares.dto

import org.e2ee.common.Share

data class ShareDto(
    val index: Int,
    val value: ByteArray
)

fun ShareDto.toShare(): Share {
    return Share(
        index = this.index,
        value = this.value
    )
}

fun Share.toShareDto(): ShareDto {
    return ShareDto(
        index = this.index,
        value = this.value
    )
}