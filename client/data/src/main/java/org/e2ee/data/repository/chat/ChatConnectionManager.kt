package org.e2ee.data.repository.chat

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.network.NetworkConfig
import org.e2ee.data.remote.websocket.ChatStompClient
import javax.inject.Inject

class ChatConnectionManager @Inject constructor(
    private val tokenManager: TokenManager,
    private val networkConfig: NetworkConfig,
    private val chatMessageReceiver: ChatMessageReceiver,
    private val chatMessageStatusUpdater: ChatMessageStatusUpdater
) {

    private val connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var stompClient: ChatStompClient? = null

    fun connect() {
        if (stompClient != null) return

        val accessToken = tokenManager.getAccessToken()
            ?: throw IllegalStateException("Cannot connect WebSocket: no access token found")

        lateinit var client: ChatStompClient

        client = ChatStompClient(
            serverUrl = networkConfig.websocketUrl,
            accessToken = accessToken,

            onMessageReceived = { message ->
                connectionScope.launch {
                    chatMessageReceiver.receiveIncomingMessage(
                        encryptedMessage = message,
                        stompClient = client
                    )
                }
            },

            onMessageStatusReceived = { ack ->
                connectionScope.launch {
                    chatMessageStatusUpdater.updateStatus(
                        messageId = ack.messageId,
                        status = ack.status
                    )
                }
            },

            onConnected = {
                println("Connected to chat WebSocket")
            },

            onError = { error ->
                println("WebSocket error: $error")
            }
        )

        stompClient = client
        client.connect()
    }

    suspend fun sendMessage(
        receiverId: String,
        content: String,
        sender: ChatMessageSender
    ) {
        val client = stompClient
            ?: throw IllegalStateException("Chat WebSocket is not connected")

        sender.sendMessage(
            receiverId = receiverId,
            content = content,
            stompClient = client
        )
    }

    fun disconnect() {
        stompClient?.disconnect()
        stompClient = null
    }
}