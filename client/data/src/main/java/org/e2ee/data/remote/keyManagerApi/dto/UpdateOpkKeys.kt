package org.e2ee.data.remote.keyManagerApi.dto

data class UpdateOpkKeys(
    val userId: Long,
    val opkMap: Map<String, ByteArray>,
)
