package org.e2ee.data.remote.network

data class NetworkConfig(
    val ip: String = "10.51.33.88",
    val baseUrl: String = "http://$ip:5000",
    val websocketUrl: String = "$baseUrl/ws"
)