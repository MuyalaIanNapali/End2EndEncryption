package org.e2ee.client.navigation

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import org.e2ee.client.R
import org.e2ee.client.auth.screen.CreateAccountScreen
import org.e2ee.client.auth.screen.LoginScreen
import org.e2ee.client.ui.elements.AuthTabSwitcher
import org.e2ee.client.ui.elements.HeaderSection

@Composable
fun AuthNavigation(
    modifier: Modifier = Modifier,
    onAuthSuccess: () -> Unit = {}
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

    val isLogin = currentRoute == Route.Auth.Login
    val isRegister = currentRoute == Route.Auth.Register

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding(),
    ) {
        HeaderSection(
            title = when {
                isLogin -> stringResource(R.string.login_title)
                isRegister -> stringResource(R.string.register_title)
                else -> ""
            },
            subtitle = stringResource(R.string.header_subtitle),
            onBackClick = {
                authBackStack.removeLastOrNull()
            }
        )

        Column(
            modifier = Modifier
                .padding(horizontal = 20.dp)
                .padding(top = 24.dp)
        ) {
            AuthTabSwitcher(
                selectedRoute = currentRoute as? Route.Auth,
                onLoginClick = {
                    switchAuthTab(Route.Auth.Login)
                },
                onRegisterClick = {
                    switchAuthTab(Route.Auth.Register)
                }
            )

            Spacer(modifier = Modifier.height(24.dp))

            NavDisplay(
                backStack = authBackStack,
                entryDecorators = listOf(
                    rememberSaveableStateHolderNavEntryDecorator(),
                    rememberViewModelStoreNavEntryDecorator()
                ),
                entryProvider = entryProvider {
                    entry<Route.Auth.Login> {
                        LoginScreen(
                            onLoginSuccess = {
                                onAuthSuccess()
                            }
                        )
                    }

                    entry<Route.Auth.Register> {
                        CreateAccountScreen(
                            onCreateAccountSuccess = {
                                onAuthSuccess()
                            }
                        )
                    }
                }
            )
        }
    }
}
