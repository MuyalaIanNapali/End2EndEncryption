package org.e2ee.client.navigation

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import kotlinx.coroutines.launch
import org.e2ee.client.main.screen.ChatScreen
import org.e2ee.client.main.screen.MessagesScreen
import org.e2ee.client.main.screen.SearchScreen
import org.e2ee.client.main.screen.SettingsScreen
import org.e2ee.client.main.viewmodel.MainViewModel

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun MainNavigation(
    modifier: Modifier = Modifier,
    onLogOut: () -> Unit = {},
    mainViewModel: MainViewModel = hiltViewModel()
) {
    val mainBackStack = rememberNavBackStack(Route.Main.Messages)

    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    DisposableEffect(Unit) {
        mainViewModel.connectWebSocket()

        onDispose {
            mainViewModel.disconnectWebSocket()
        }
    }

    Scaffold(
        modifier = modifier,
        snackbarHost = {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                SnackbarHost(hostState = snackbarHostState)
            }
        }
    ) { _ ->

        NavDisplay(
            modifier = Modifier,
            backStack = mainBackStack,
            entryDecorators = listOf(
                rememberSaveableStateHolderNavEntryDecorator(),
                rememberViewModelStoreNavEntryDecorator()
            ),
            entryProvider = entryProvider {
                entry<Route.Main.Messages> {
                    MessagesScreen(
                        modifier = Modifier,
                        onChatCardClick = { sessionId, contactId, contactName, contactEmail ->
                            mainBackStack.add(
                                Route.Main.Chat(
                                    sessionId = sessionId,
                                    receiverId = contactId,
                                    username = contactName,
                                    email = contactEmail
                                )
                            )
                        },
                        onLogoutClick = {
                            coroutineScope.launch {
                                val result = snackbarHostState.showSnackbar(
                                    message = "Do you want to log out?",
                                    actionLabel = "Logout",
                                    withDismissAction = true,
                                    duration = SnackbarDuration.Long,
                                )

                                if (result == SnackbarResult.ActionPerformed) {
                                    mainViewModel.logout {
                                        onLogOut()
                                    }
                                }
                            }
                        },
                        onFabClick = {
                            mainBackStack.add(Route.Main.Search)
                        },
                        onSettingsClick = {
                            mainBackStack.add(Route.Main.Settings)
                        }
                    )
                }

                entry<Route.Main.Chat> { chatRoute ->
                    ChatScreen(
                        sessionId = chatRoute.sessionId,
                        receiverId = chatRoute.receiverId,
                        username = chatRoute.username,
                        email = chatRoute.email,
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
                                    receiverId = userDetails.id.toString(),
                                    username = userDetails.username,
                                    email = userDetails.email
                                )
                            )
                        }
                    )
                }

                entry<Route.Main.Settings> {
                    SettingsScreen(
                        onBackClick = {
                            mainBackStack.removeLastOrNull()
                        }
                    )
                }
            }
        )
    }
}