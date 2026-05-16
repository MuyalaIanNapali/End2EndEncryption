package org.e2ee.data.opk

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "one_time_pre_keys")
data class OneTimePreKeys(
    @PrimaryKey
    val opkId: String,
    val publicKey: ByteArray,
    val privateKey: ByteArray,

    val uploaded: Boolean = false,
    val consumed: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as OneTimePreKeys

        if (uploaded != other.uploaded) return false
        if (consumed != other.consumed) return false
        if (opkId != other.opkId) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = uploaded.hashCode()
        result = 31 * result + consumed.hashCode()
        result = 31 * result + opkId.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        return result
    }
}