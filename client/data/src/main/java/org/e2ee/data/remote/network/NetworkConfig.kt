package org.e2ee.data.remote.network

data class NetworkConfig(
    val ip: String = "46.96.32.74",
    val baseUrl: String = "http://$ip:5000",
    val websocketUrl: String = "$baseUrl/ws"
)