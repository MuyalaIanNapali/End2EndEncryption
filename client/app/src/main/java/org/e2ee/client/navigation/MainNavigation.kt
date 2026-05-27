package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import org.e2ee.client.main.screen.ChatScreen
import org.e2ee.client.main.screen.MessagesScreen

@Composable
fun MainNavigation(
    modifier: Modifier = Modifier,
    onLogOut: () -> Unit = {}
) {
    val mainBackStack = rememberNavBackStack(Route.Main.Messages)

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
                // TODO
            }

            entry<Route.Main.Settings> {
                // TODO
            }
        }
    )
}
