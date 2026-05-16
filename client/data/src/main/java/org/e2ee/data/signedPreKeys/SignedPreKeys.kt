package org.e2ee.data.signedPreKeys

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import org.e2ee.data.userKeys.UserKeys

@Entity(
    tableName = "signed_pre_keys",
    foreignKeys = [
        ForeignKey(
            entity = UserKeys::class,
            parentColumns = ["id"],
            childColumns = ["localUserId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["localUserId"])
    ]
)
data class SignedPreKeys(
    @PrimaryKey
    val signedPreKeyId: String,

    val localUserId: Int = 1,

    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val signature: ByteArray,

    val createdAt: Long = System.currentTimeMillis(),

    // Active lifetime: 30 days
    val expiresAt: Long = createdAt + 30L * 24 * 60 * 60 * 1000,

    // After it becomes inactive, keep it for 48 hours
    val deleteAfter: Long? = null,

    val uploaded: Boolean = false,
    val active: Boolean = false
)