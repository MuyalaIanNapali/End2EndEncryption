package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import org.e2ee.client.main.screen.ChatScreen
import org.e2ee.client.main.screen.MessagesScreen
import org.e2ee.client.main.screen.SearchScreen
import org.e2ee.client.main.viewmodel.MainViewModel

@Composable
fun MainNavigation(
    modifier: Modifier = Modifier,
    onLogOut: () -> Unit = {},
    mainViewModel: MainViewModel = hiltViewModel()
) {
    val mainBackStack = rememberNavBackStack(Route.Main.Messages)

    DisposableEffect(Unit) {
        mainViewModel.connectWebSocket()

        onDispose {
            mainViewModel.disconnectWebSocket()
        }
    }

    NavDisplay(
        modifier = modifier,
        backStack = mainBackStack,
        entryDecorators = listOf(
            rememberSaveableStateHolderNavEntryDecorator(),
            rememberViewModelStoreNavEntryDecorator()
        ),
        entryProvider = entryProvider {
            entry<Route.Main.Messages> {
                MessagesScreen(
                    onChatCardClick = { sessionId, contactName ->
                        mainBackStack.add(
                            Route.Main.Chat(
                                sessionId = sessionId,
                                username = contactName
                            )
                        )
                    },
                    onSettingsClick = {
                        mainBackStack.add(Route.Main.Settings)
                    },
                    onFabClick = {
                        mainBackStack.add(Route.Main.Search)
                    }
                )
            }

            entry<Route.Main.Chat> { chatRoute ->
                ChatScreen(
                    sessionId = chatRoute.sessionId,
                    username = chatRoute.username,
                    onBackClick = {
                        mainBackStack.removeLastOrNull()
                    },
                    onSettingsClick = {
                        mainBackStack.add(Route.Main.Settings)
                    }
                )
            }

            entry<Route.Main.Search> {
                SearchScreen(
                    onUserClick = { userDetails ->
                        mainBackStack.add(
                            Route.Main.Chat(
                                sessionId = null,
                                username = userDetails.username
                            )
                        )
                    }
                )
            }

            entry<Route.Main.Settings> {
                // TODO
            }
        }
    )
}