package org.e2ee.data.remote.network

data class NetworkConfig(
    //val ip: String = "20.164.17.8",
    val ip: String = "10.51.34.77",
    val baseUrl: String = "http://$ip:5000",
    val websocketUrl: String = "$baseUrl/ws"
)