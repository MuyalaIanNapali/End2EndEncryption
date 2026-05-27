package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import kotlin.collections.listOf

@Composable
fun NavigationRoot(
    modifier: Modifier = Modifier
){
    val rootBackStack = rememberNavBackStack(Route.Auth)

    NavDisplay(
        backStack = rootBackStack,
        entryDecorators = listOf(
            rememberSaveableStateHolderNavEntryDecorator(),
            rememberViewModelStoreNavEntryDecorator()
        ),
        entryProvider = entryProvider {
            entry<Route.Auth> {
                AuthNavigation(
                    onAuthSuccess = {
                        rootBackStack.add(Route.Main)
                    }
                )
            }

            entry<Route.Main> {
                MainNavigation(
                    onLogOut = {
                        rootBackStack.clear()
                        rootBackStack.add(Route.Auth)
                    }
                )
            }
        }
    )
}

@Preview
@Composable
fun NavigationRootPreview() {
    NavigationRoot()
}