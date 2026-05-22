package org.e2ee.data.remote.websocket

import kotlinx.serialization.json.Json

object WebSocketJson {

    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
        isLenient = true
    }
}