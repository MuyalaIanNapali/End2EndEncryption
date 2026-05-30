package org.e2ee.data.local.messages

import androidx.room.TypeConverter

class MessageStatusConverter {

    @TypeConverter
    fun fromMessageStatus(status: MessageStatus): String {
        return status.name
    }

    @TypeConverter
    fun toMessageStatus(value: String): MessageStatus {
        return MessageStatus.valueOf(value)
    }
}