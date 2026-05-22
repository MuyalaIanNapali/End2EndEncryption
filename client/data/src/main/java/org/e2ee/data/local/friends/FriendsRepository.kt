package org.e2ee.data.local.friends

import androidx.annotation.WorkerThread
import javax.inject.Inject

class FriendsRepository @Inject constructor(
    private val dao: FriendsDao
) {

    @WorkerThread
    suspend fun addFriend(friend: Friends) {
        dao.insertFriend(friend)
    }

    @WorkerThread
    suspend fun getAllFriends(): List<Friends> {
        return dao.getAllFriends()
    }

    @WorkerThread
    suspend fun deleteFriendById(userId: Long) {
        dao.deleteFriendById(userId)
    }

    @WorkerThread
    suspend fun getFriendByUsername(username: String): Friends? {
        return dao.getFriendByUsername(username)
    }
}