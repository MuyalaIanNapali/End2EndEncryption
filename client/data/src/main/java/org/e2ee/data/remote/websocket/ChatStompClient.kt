package org.e2ee.data.remote.websocket

import com.google.gson.Gson
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

class ChatStompClient(
    private val serverUrl: String,
    private val accessToken: String,
    private val onMessageReceived: (ChatMessage) -> Unit,
    private val onMessageStatusReceived: (MessageAck) -> Unit,
    private val onConnected: () -> Unit = {},
    private val onError: (String) -> Unit = {}
) {

    private val client = OkHttpClient()
    private val gson = Gson()
    private var webSocket: WebSocket? = null

    fun connect() {
        val request = Request.Builder()
            .url(serverUrl)
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: okhttp3.Response) {
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
                response: okhttp3.Response?
            ) {
                onError(t.message ?: "WebSocket error")
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                onError("WebSocket closed: $reason")
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
                subscribeToMessages()
                subscribeToMessageStatus()
                syncPendingMessages()
                onConnected()
            }

            frame.startsWith("MESSAGE") -> {
                val destination = extractHeader(frame, "destination")
                val body = extractBody(frame)

                when {
                    destination?.contains("/queue/messages") == true -> {
                        val message = gson.fromJson(body, ChatMessage::class.java)
                        onMessageReceived(message)
                    }

                    destination?.contains("/queue/message-status") == true -> {
                        val ack = gson.fromJson(body, MessageAck::class.java)
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
        val body = gson.toJson(request)

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
        val body = gson.toJson(request)

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
        val frame = buildString {
            append("DISCONNECT\n")
            append("\n")
            append('\u0000')
        }

        webSocket?.send(frame)
        webSocket?.close(1000, "Client disconnected")
        webSocket = null
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
}