package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import java.lang.reflect.Modifier
import kotlin.collections.listOf

@Composable
fun NavigationRoot(
    modifier: Modifier
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
                //TODO
            }

            entry<Route.Main> {
                //TODO
            }
        }
    )
}