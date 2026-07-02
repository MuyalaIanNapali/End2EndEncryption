package org.e2ee.data.repository.chat

import android.util.Log
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import org.e2ee.data.local.messages.MessagesRepository
import org.e2ee.data.repository.mapper.toDomain
import org.e2ee.data.repository.mapper.toMessage
import org.e2ee.domain.model.ChatRoomDomain
import org.e2ee.domain.model.ConnectionState
import javax.inject.Inject
import org.e2ee.domain.repository.ChatRepository as ChatRepositoryInterface
import org.e2ee.domain.model.Message

class ChatRepository @Inject constructor(
    private val chatConnectionManager: ChatConnectionManager,
    private val chatMessageSender: ChatMessageSender,
    private val chatMessageObserver: ChatMessageObserver,
    private val chatRoomManager: ChatRoomManager,
    private val messagesRepository: MessagesRepository
): ChatRepositoryInterface {

    override val connectionState: StateFlow<ConnectionState>
        get() = chatConnectionManager.connectionState

    override fun observeMessages(
        sessionId: String
    ): Flow<List<Message>> {
        return chatMessageObserver
            .observeMessages(sessionId)
            .map { messages ->
                messages.map { it.toMessage() }
            }
    }

    override fun connect() {
        chatConnectionManager.connect()
    }

    override suspend fun sendMessage(
        receiverId: String,
        username: String,
        content: String
    ) : String {
        return chatConnectionManager.sendMessage(
            receiverId = receiverId,
            username = username,
            content = content,
            sender = chatMessageSender
        )
    }

    override fun disconnect() {
        chatConnectionManager.disconnect()
    }

    override fun getChatRooms(): Flow<List<ChatRoomDomain>> {
        return chatRoomManager.getAllChatRoomsForUser().map { chatRooms ->
            chatRooms.map { it.toDomain() }
        }
    }

    suspend fun getMessagesForSession(sessionId: String): List<Message> {
        return messagesRepository.getMessagesBySessionId(sessionId).map { it.toMessage() }
    }

    override suspend fun getUnreadMessageCount(sessionId: String): Int {
        return messagesRepository.countUnreadMessages(sessionId)
    }

    override suspend fun getChatRoomByReceiverId(receiverId: String): ChatRoomDomain? {
        val chatRoom = chatRoomManager.getChatRoomByOtherUserId(receiverId)
        return chatRoom?.toDomain()
    }

    override suspend fun updateLastMessage(sessionId: String, lastMessage: String, lastMessageTime: Long) {
        chatRoomManager.updateLastMessage(sessionId, lastMessage, lastMessageTime)
    }

    override suspend fun markMessagesAsRead(sessionId: String) {
        messagesRepository.markMessagesAsRead(sessionId)
    }
}