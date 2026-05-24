package org.e2ee.client.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay

@Composable
fun SettingsNavigation(
    modifier: Modifier
){
    val rootBackStack = rememberNavBackStack(Route.Settings.General)

    NavDisplay(
        backStack = rootBackStack,
        entryDecorators = listOf(
            rememberSaveableStateHolderNavEntryDecorator(),
            rememberViewModelStoreNavEntryDecorator()
        ),
        entryProvider = entryProvider {
            entry<Route.Settings.General> {
                //TODO
            }

            entry<Route.Settings.Account> {
                //TODO
            }

            entry<Route.Settings.ProfileSettings> {
                //TODO
            }
        }
    )
}