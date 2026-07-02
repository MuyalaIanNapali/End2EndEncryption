package org.e2ee.data.remote.websocket

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.e2ee.domain.model.ConnectionState
import java.util.concurrent.TimeUnit

class ChatStompClient(
    private val serverUrl: String,
    private val accessToken: String,
    private val onMessageReceived: (ChatMessage) -> Unit,
    private val onMessageStatusReceived: (MessageAck) -> Unit,
    private val onConnected: () -> Unit = {},
    private val onError: (String) -> Unit = {}
) {

    private val client = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)
        .build()

    private val reconnectScope = CoroutineScope(Dispatchers.IO)

    private var reconnectJob: Job? = null

    private var reconnectDelay = 5_000L

    private val maxReconnectDelay = 60_000L

    @Volatile
    private var manuallyDisconnected = false

    private val _state = MutableStateFlow(ConnectionState.DISCONNECTED)
    val state = _state.asStateFlow()

    private var heartbeatJob: Job? = null

    private var webSocket: WebSocket? = null

    fun connect() {
        manuallyDisconnected = false

        if (webSocket != null) return

        val request = Request.Builder()
            .url(serverUrl)
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: okhttp3.Response) {
                _state.value = ConnectionState.CONNECTING
                connectStomp()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleFrame(text)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                handleFrame(bytes.utf8())
            }

            override fun onFailure(
                webSocket: WebSocket,
                t: Throwable,
                response: Response?
            ) {

                heartbeatJob?.cancel()

                this@ChatStompClient.webSocket = null

                _state.value = ConnectionState.DISCONNECTED

                onError(t.message ?: "WebSocket error")

                scheduleReconnect()
            }

            override fun onClosed(
                webSocket: WebSocket,
                code: Int,
                reason: String
            ) {

                heartbeatJob?.cancel()

                this@ChatStompClient.webSocket = null

                _state.value = ConnectionState.DISCONNECTED

                onError("WebSocket closed: $reason")

                scheduleReconnect()
            }
        })
    }

    private fun connectStomp() {
        val frame = buildString {
            append("CONNECT\n")
            append("accept-version:1.2\n")
            append("heart-beat:10000,10000\n")
            append("Authorization:Bearer $accessToken\n")
            append("\n")
            append('\u0000')
        }

        webSocket?.send(frame)
    }

    private fun handleFrame(frame: String) {
        when {
            frame.startsWith("CONNECTED") -> {
                reconnectDelay = 5_000L
                reconnectJob?.cancel()

                subscribeToMessages()
                subscribeToMessageStatus()
                syncPendingMessages()
                startHeartbeat()

                _state.value = ConnectionState.CONNECTED
                onConnected()
            }

            frame.startsWith("MESSAGE") -> {
                val destination = extractHeader(frame, "destination")
                val body = extractBody(frame)

                when {
                    destination?.contains("/queue/messages") == true -> {
                        //use serializable data classes instead of gson for better performance and type safety
                        val message = WebSocketJson.json.decodeFromString<ChatMessage>(body)
                        onMessageReceived(message)
                    }

                    destination?.contains("/queue/message-status") == true -> {
                        val ack = WebSocketJson.json.decodeFromString<MessageAck>(body)
                        onMessageStatusReceived(ack)
                    }
                }
            }

            frame.startsWith("ERROR") -> {
                onError(frame)
            }
        }
    }

    private fun subscribeToMessages() {
        val frame = buildString {
            append("SUBSCRIBE\n")
            append("id:sub-messages\n")
            append("destination:/user/queue/messages\n")
            append("\n")
            append('\u0000')
        }

        webSocket?.send(frame)
    }

    private fun subscribeToMessageStatus() {
        val frame = buildString {
            append("SUBSCRIBE\n")
            append("id:sub-status\n")
            append("destination:/user/queue/message-status\n")
            append("\n")
            append('\u0000')
        }

        webSocket?.send(frame)
    }

    fun sendChatMessage(request: ChatRequest) {
        val body = WebSocketJson.json.encodeToString(request)

        val frame = buildString {
            append("SEND\n")
            append("destination:/app/chat\n")
            append("content-type:application/json\n")
            append("\n")
            append(body)
            append('\u0000')
        }

        webSocket?.send(frame)
    }

    fun sendDeliveredReceipt(request: DeliveryReceiptRequest) {
        val body = WebSocketJson.json.encodeToString(request)

        val frame = buildString {
            append("SEND\n")
            append("destination:/app/chat/delivered\n")
            append("content-type:application/json\n")
            append("\n")
            append(body)
            append('\u0000')
        }

        webSocket?.send(frame)
    }

    fun syncPendingMessages() {
        val frame = buildString {
            append("SEND\n")
            append("destination:/app/chat/sync\n")
            append("\n")
            append('\u0000')
        }

        webSocket?.send(frame)
    }

    fun disconnect() {

        manuallyDisconnected = true

        reconnectJob?.cancel()
        heartbeatJob?.cancel()

        val frame = buildString {
            append("DISCONNECT\n")
            append("\n")
            append('\u0000')
        }

        webSocket?.send(frame)
        webSocket?.close(1000, "Client disconnected")

        webSocket = null

        _state.value = ConnectionState.DISCONNECTED
    }

    private fun extractHeader(frame: String, headerName: String): String? {
        return frame
            .lines()
            .firstOrNull { it.startsWith("$headerName:") }
            ?.substringAfter("$headerName:")
            ?.trim()
    }

    private fun extractBody(frame: String): String {
        return frame
            .substringAfter("\n\n", "")
            .removeSuffix("\u0000")
            .trim()
    }

    private fun startHeartbeat() {

        heartbeatJob?.cancel()

        heartbeatJob = CoroutineScope(Dispatchers.IO).launch {

            while (isActive) {

                delay(10_000)

                webSocket?.send("\n")
            }
        }
    }

    private fun scheduleReconnect() {

        if (manuallyDisconnected) return

        // Already trying to reconnect
        if (reconnectJob?.isActive == true) return

        reconnectJob = reconnectScope.launch {

            while (!manuallyDisconnected &&
                _state.value != ConnectionState.CONNECTED) {

                delay(reconnectDelay)

                try {

                    webSocket = null
                    connect()

                } catch (_: Exception) {
                }

                reconnectDelay =
                    (reconnectDelay * 2)
                        .coerceAtMost(maxReconnectDelay)
            }
        }
    }
}