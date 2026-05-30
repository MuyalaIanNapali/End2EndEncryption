package org.e2ee.data.local.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import org.e2ee.data.local.chatRoom.ChatRoom
import org.e2ee.data.local.chatRoom.ChatRoomDao
import org.e2ee.data.local.friends.Friends
import org.e2ee.data.local.friends.FriendsDao
import org.e2ee.data.local.messages.MessageStatusConverter
import org.e2ee.data.local.messages.Messages
import org.e2ee.data.local.messages.MessagesDao
import org.e2ee.data.local.opk.OneTimePreKeys
import org.e2ee.data.local.opk.OneTimePreKeysDao
import org.e2ee.data.local.ratchetStates.RatchetStates
import org.e2ee.data.local.ratchetStates.RatchetStatesDao
import org.e2ee.data.local.signedPreKeys.SignedPreKeys
import org.e2ee.data.local.signedPreKeys.SignedPreKeysDao
import org.e2ee.data.local.user.User
import org.e2ee.data.local.user.UserDao
import org.e2ee.data.local.userKeys.UserKeys
import org.e2ee.data.local.userKeys.UserKeysDao

@Database(
    entities = [
        UserKeys::class,
        OneTimePreKeys::class,
        SignedPreKeys::class,
        RatchetStates::class,
        User::class,
        Friends::class,
        ChatRoom::class,
        Messages::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(MessageStatusConverter::class)
abstract class ClientDatabase : RoomDatabase() {

    abstract fun oneTimePreKeysDao(): OneTimePreKeysDao
    abstract fun userKeysDao(): UserKeysDao
    abstract fun signedPreKeysDao(): SignedPreKeysDao
    abstract fun ratchetStatesDao(): RatchetStatesDao
    abstract fun userDao(): UserDao
    abstract fun friendsDao(): FriendsDao
    abstract fun chatRoomDao(): ChatRoomDao
    abstract fun messagesDao(): MessagesDao
}