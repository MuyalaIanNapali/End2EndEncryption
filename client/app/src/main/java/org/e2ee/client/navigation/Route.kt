package org.e2ee.client.navigation

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

@Serializable
sealed interface Route: NavKey {

    @Serializable
    data object Auth: Route {

        @Serializable
        data object Login : Route

        @Serializable
        data object Register : Route

        @Serializable
        data object ForgotPassword : Route
    }

    @Serializable
    data object Main: Route {

        @Serializable
        data object Chats : Route

        @Serializable
        data class Chat(val chatId: String) : Route

        @Serializable
        data object Search : Route

    }

    @Serializable
    data object Settings: Route{

        @Serializable
        data object General: Route, NavKey

        @Serializable
        data object Account: Route, NavKey

        @Serializable
        data object ProfileSettings: Route, NavKey


    }
}