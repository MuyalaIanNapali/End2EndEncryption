package org.e2ee.client.navigation

import android.annotation.SuppressLint
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope
import org.e2ee.client.R
import org.e2ee.client.main.screen.ChatScreen
import org.e2ee.client.main.screen.MessagesScreen
import org.e2ee.client.main.screen.SearchScreen
import org.e2ee.client.main.screen.SettingsScreen
import org.e2ee.client.main.viewmodel.MainViewModel

private const val SLIDE_DURATION = 300

// Push: incoming slides in from right, outgoing exits to the left
private val slideForward: ContentTransform =
    slideInHorizontally(tween(SLIDE_DURATION)) { fullWidth -> fullWidth } togetherWith
            slideOutHorizontally(tween(SLIDE_DURATION)) { fullWidth -> -fullWidth }

// Pop: incoming slides in from left, outgoing exits to the right
private val slideBack: ContentTransform =
    slideInHorizontally(tween(SLIDE_DURATION)) { fullWidth -> -fullWidth } togetherWith
            slideOutHorizontally(tween(SLIDE_DURATION)) { fullWidth -> fullWidth }

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun MainNavigation(
    modifier: Modifier = Modifier,
    onLogOut: () -> Unit = {},
    mainViewModel: MainViewModel = hiltViewModel()
) {
    val mainBackStack = rememberNavBackStack(Route.Main.Messages)

    // Track previous backstack size to determine push vs pop direction
    var previousStackSize by remember { mutableIntStateOf(mainBackStack.size) }
    val isPopping = mainBackStack.size < previousStackSize

    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    DisposableEffect(Unit) {
        mainViewModel.connectWebSocket()
        onDispose { mainViewModel.disconnectWebSocket() }
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
            // Single transitionSpec that chooses direction based on stack size change
            transitionSpec = {
                val transform = if (isPopping) slideBack else slideForward
                // Update tracked size after the lambda runs
                previousStackSize = mainBackStack.size
                transform
            },
            entryProvider = entryProvider {
                entry<Route.Main.Messages> {
                    val logoutPrompt = androidx.compose.ui.res.stringResource(R.string.logout_prompt)
                    val logoutAction = androidx.compose.ui.res.stringResource(R.string.logout_action)

                    MessagesScreen(
                        modifier = Modifier,
                        onChatCardClick = { sessionId, contactId, contactName, contactEmail ->
                            previousStackSize = mainBackStack.size
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
                                    message = logoutPrompt,
                                    actionLabel = logoutAction,
                                    withDismissAction = true,
                                    duration = SnackbarDuration.Long,
                                )
                                if (result == SnackbarResult.ActionPerformed) {
                                    mainViewModel.logout { onLogOut() }
                                }
                            }
                        },
                        onFabClick = {
                            previousStackSize = mainBackStack.size
                            mainBackStack.add(Route.Main.Search)
                        },
                        onSettingsClick = {
                            previousStackSize = mainBackStack.size
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
                            previousStackSize = mainBackStack.size
                            mainBackStack.removeLastOrNull()
                        },
                        onSettingsClick = {
                            previousStackSize = mainBackStack.size
                            mainBackStack.add(Route.Main.Settings)
                        }
                    )
                }

                entry<Route.Main.Search> {
                    SearchScreen(
                        onUserClick = { userDetails ->
                            previousStackSize = mainBackStack.size
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
                            previousStackSize = mainBackStack.size
                            mainBackStack.removeLastOrNull()
                        }
                    )
                }
            }
        )
    }
}