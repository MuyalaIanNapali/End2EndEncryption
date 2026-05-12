package server.keymanager.dto

data class UpdateOpkKeys(
    val userId: Long,
    val opkMap: Map<String, ByteArray>,
)
