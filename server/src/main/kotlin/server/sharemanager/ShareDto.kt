package server.sharemanager

import jakarta.persistence.Embeddable

@Embeddable
data class ShareDto(
    val index: Int,
    val value: ByteArray
)