package org.e2ee.data.remote.network

object AppNetworkConfig {

    object AppNetworkConfig {
        val dev = NetworkConfig(
            baseUrl = "http://192.168.1.10:5000/",
            websocketUrl = "ws://192.168.1.10:5000/ws"
        )
    }
}