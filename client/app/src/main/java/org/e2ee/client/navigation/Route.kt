package org.e2ee.client.navigation

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

@Serializable
sealed interface Route: NavKey {

    @Serializable
    data object Splash : Route

    @Serializable
    data object Auth : Route {

        @Serializable
        data object Login : Route

        @Serializable
        data object Register : Route

    }

    @Serializable
    data object Main : Route {

        @Serializable
        data object Messages : Route

        @Serializable
        data class Chat(
            val sessionId: String?,
            val receiverId: String,
            val username: String,
            val email: String
        ) : Route

        @Serializable
        data object Search : Route

        @Serializable
        data object Settings : Route

    }
}