package org.e2ee.data.local.ratchetStates

data class SkippedMessageKey(
    val id: SkippedMessageKeyId,
    val messageKey: ByteArray
)

data class SkippedMessageKeyId(
    val headerKey: ByteArray,
    val messageNumber: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SkippedMessageKeyId) return false

        return messageNumber == other.messageNumber &&
                headerKey.contentEquals(other.headerKey)
    }

    override fun hashCode(): Int {
        var result = headerKey.contentHashCode()
        result = 31 * result + messageNumber
        return result
    }
}
