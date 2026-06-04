package org.e2ee.data.local.signedPreKeys

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import org.e2ee.data.local.signedPreKeys.SignedPreKeyBundle

@Dao
interface SignedPreKeysDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSignedPreKey(signedPreKey: SignedPreKeys)

    @Query("SELECT * FROM signed_pre_keys WHERE signedPreKeyId = :signedPreKeyId LIMIT 1")
    suspend fun getSignedPreKeyById(signedPreKeyId: String): SignedPreKeys?

     @Query("SELECT * FROM signed_pre_keys WHERE active = 1")
     suspend fun getActiveSignedPreKey(): SignedPreKeys?

     @Query("SELECT * FROM signed_pre_keys")
     suspend fun getAllSignedPreKeys(): List<SignedPreKeys>

     @Query(
            """
           UPDATE signed_pre_keys
           SET active = 0, deleteAfter = :deleteAfter
           WHERE signedPreKeyId = :signedPreKeyId
            """
     )
     suspend fun markAsInactive(
         signedPreKeyId: String,
         deleteAfter: Long
     )

     @Query(
            """
           DELETE FROM signed_pre_keys
           WHERE active = 0
           AND deleteAfter IS NOT NULL
           AND deleteAfter <= :now
            """
     )
     suspend fun deleteExpiredInactiveSignedPreKeys(now: Long)

     @Query("UPDATE signed_pre_keys SET uploaded = 1 WHERE signedPreKeyId = :signedPreKeyId")
     suspend fun markAsUploaded(signedPreKeyId: String)

      @Query(
          """
             SELECT signedPreKeyId AS keyId, publicKey AS signedPreKey, signature
                FROM signed_pre_keys
                WHERE active = 1
         """
     ) suspend fun getActiveSignedPreKeyBundle(): SignedPreKeyBundle?

      // Use getSignedPreKeyById to retrieve the full SignedPreKeys entity when a key pair is needed.





}