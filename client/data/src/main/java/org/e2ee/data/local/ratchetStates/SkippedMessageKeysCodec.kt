package org.e2ee.data.local.ratchetStates

import java.nio.ByteBuffer

object SkippedMessageKeysCodec {

    fun encodeList(keys: List<SkippedMessageKey>): ByteArray {
        val encodedItems = keys.map { encode(it) }

        val totalSize = 4 + encodedItems.sumOf { 4 + it.size }

        val buffer = ByteBuffer.allocate(totalSize)

        buffer.putInt(encodedItems.size)

        for (item in encodedItems) {
            buffer.putInt(item.size)
            buffer.put(item)
        }

        return buffer.array()
    }

    fun encode(skipped: SkippedMessageKey): ByteArray {
        val headerKey = skipped.id.headerKey
        val messageKey = skipped.messageKey
        val messageNumber = skipped.id.messageNumber

        val buffer = ByteBuffer.allocate(
            4 + headerKey.size +
                    4 +
                    4 + messageKey.size
        )

        buffer.putInt(headerKey.size)
        buffer.put(headerKey)

        buffer.putInt(messageNumber)

        buffer.putInt(messageKey.size)
        buffer.put(messageKey)

        return buffer.array()
    }

    fun decodeList(bytes: ByteArray): List<SkippedMessageKey> {
        if (bytes.isEmpty()) return emptyList()

        val buffer = ByteBuffer.wrap(bytes)

        val count = buffer.getInt()
        require(count >= 0) {
            "Invalid skipped message key count"
        }

        val result = mutableListOf<SkippedMessageKey>()

        repeat(count) {
            val itemLength = buffer.getInt()
            require(itemLength > 0 && itemLength <= buffer.remaining()) {
                "Invalid skipped message key item length"
            }

            val itemBytes = ByteArray(itemLength)
            buffer.get(itemBytes)

            result.add(decode(itemBytes))
        }

        require(!buffer.hasRemaining()) {
            "Unexpected extra bytes in skipped message key list encoding"
        }

        return result
    }

    fun decode(bytes: ByteArray): SkippedMessageKey {
        val buffer = ByteBuffer.wrap(bytes)

        val headerKeyLength = buffer.getInt()
        require(headerKeyLength > 0 && headerKeyLength <= buffer.remaining()) {
            "Invalid header key length"
        }

        val headerKey = ByteArray(headerKeyLength)
        buffer.get(headerKey)

        val messageNumber = buffer.getInt()

        val messageKeyLength = buffer.getInt()
        require(messageKeyLength > 0 && messageKeyLength <= buffer.remaining()) {
            "Invalid message key length"
        }

        val messageKey = ByteArray(messageKeyLength)
        buffer.get(messageKey)

        require(!buffer.hasRemaining()) {
            "Unexpected extra bytes in skipped message key encoding"
        }

        return SkippedMessageKey(
            id = SkippedMessageKeyId(
                headerKey = headerKey,
                messageNumber = messageNumber
            ),
            messageKey = messageKey
        )
    }
}