package org.e2ee.data.local.friends

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert

@Dao
interface FriendsDao {
    @Upsert
    suspend fun insertFriend(friend: Friends)

    @Query("SELECT * FROM friends")
    suspend fun getAllFriends(): List<Friends>

    @Query("DELETE FROM friends WHERE userId = :userId")
    suspend fun deleteFriendById(userId: Long)

    @Query("SELECT * FROM friends WHERE username =:username LIMIT 1")
    suspend fun getFriendByUsername(username: String): Friends?
}