package org.e2ee.data.remote.network

data class NetworkConfig(
    val baseUrl: String = "http://46.96.32.74:5000",
    val websocketUrl: String = "$baseUrl/ws"
)