package org.e2ee.data.repository.chat

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.e2ee.data.remote.auth.TokenManager
import org.e2ee.data.remote.network.NetworkConfig
import org.e2ee.data.remote.websocket.ChatStompClient
import org.e2ee.domain.model.ConnectionState
import javax.inject.Inject

class ChatConnectionManager @Inject constructor(
    private val tokenManager: TokenManager,
    private val networkConfig: NetworkConfig,
    private val chatMessageReceiver: ChatMessageReceiver,
    private val chatMessageStatusUpdater: ChatMessageStatusUpdater
) {

    private val connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var stompClient: ChatStompClient? = null

    private val _connectionState =
        MutableStateFlow(ConnectionState.DISCONNECTED)

    val connectionState = _connectionState.asStateFlow()

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

        connectionScope.launch {
            client.state.collect {
                _connectionState.value = it
            }
        }

        stompClient = client
        client.connect()
    }

    suspend fun sendMessage(
        username: String,
        receiverId: String,
        content: String,
        sender: ChatMessageSender
    ) : String {
        val client = stompClient
            ?: throw IllegalStateException("Chat WebSocket is not connected")
        Log.d("send","Sending message to $username: $content")

        return sender.sendMessage(
            receiverId = receiverId,
            username = username,
            content = content,
            stompClient = client
        )
    }

    fun disconnect() {
        stompClient?.disconnect()
        stompClient = null
    }
}