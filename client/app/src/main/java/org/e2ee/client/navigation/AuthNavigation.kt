package org.e2ee.client.navigation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import org.e2ee.client.auth.screen.ForgotPasswordScreen
import org.e2ee.client.auth.screen.LoginScreen
import org.e2ee.client.auth.screen.RegisterScreen

@Composable
fun AuthNavigation(
    modifier: Modifier = Modifier
) {
    val authBackStack = rememberNavBackStack(Route.Auth.Login)

    val currentRoute by remember {
        derivedStateOf {
            authBackStack.lastOrNull()
        }
    }

    fun switchAuthTab(route: Route) {
        if (currentRoute != route) {
            authBackStack.clear()
            authBackStack.add(route)
        }
    }

    Column(
        modifier = modifier
            .padding(horizontal = 20.dp)
            .padding(top = 24.dp)
    ) {

        Column(
            modifier = modifier
                .padding(horizontal = 20.dp)
                .padding(top = 24.dp)
        ) {
            AuthTabSwitcher(
                selectedRoute = currentRoute as Route?,
                onLoginClick = {
                    switchAuthTab(Route.Auth.Login)
                },
                onRegisterClick = {
                    switchAuthTab(Route.Auth.Register)
                }
            )

            NavDisplay(
                modifier = Modifier.padding(top = 24.dp),
                backStack = authBackStack,
                entryDecorators = listOf(
                    rememberSaveableStateHolderNavEntryDecorator(),
                    rememberViewModelStoreNavEntryDecorator()
                ),
                entryProvider = entryProvider {
                    entry<Route.Auth.Login> {
                        LoginScreen(
                            onRegisterClick = {
                                switchAuthTab(Route.Auth.Register)
                            },
                            onForgotPasswordClick = {
                                authBackStack.add(Route.Auth.ForgotPassword)
                            }
                        )
                    }

                    entry<Route.Auth.Register> {
                        RegisterScreen(
                            onLoginClick = {
                                switchAuthTab(Route.Auth.Login)
                            }
                        )
                    }

                    entry<Route.Auth.ForgotPassword> {
                        ForgotPasswordScreen(
                            onBackClick = {
                                authBackStack.removeLastOrNull()
                            }
                        )
                    }
                }
            )
        }
    }
}

@Preview
@Composable
fun AuthNavigationPreview() {
    AuthNavigation()
}