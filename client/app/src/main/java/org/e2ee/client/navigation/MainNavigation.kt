package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay

@Composable
fun MainNavigation(
    modifier: Modifier
){
    val rootBackStack = rememberNavBackStack(Route.Main.Chats)

    NavDisplay(
        backStack = rootBackStack,
        entryDecorators = listOf(
            rememberSaveableStateHolderNavEntryDecorator(),
            rememberViewModelStoreNavEntryDecorator()
        ),
        entryProvider = entryProvider {
            entry<Route.Main.Chats> {
                //TODO
            }

            entry<Route.Main.Chat> {
                //TODO
            }

            entry<Route.Settings> {
                //TODO
            }
        }
    )
}