package com.evtimov.doors.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.evtimov.doors.di.ServiceLocator
import com.evtimov.doors.ui.screens.DoorListScreen
import com.evtimov.doors.ui.screens.EnrollmentScreen
import com.evtimov.doors.ui.screens.HistoryScreen
import com.evtimov.doors.ui.screens.SettingsScreen

object Routes {
    const val ENROLL = "enroll"
    const val DOORS = "doors"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
}

@Composable
fun AppNavigation(activity: FragmentActivity) {
    val navController = rememberNavController()
    var enrolled by remember { mutableStateOf(ServiceLocator.repository.isEnrolled) }

    // The server can end a session at any moment - a revoked device, a
    // detected refresh token reuse. The app follows rather than retrying.
    LaunchedEffect(Unit) {
        ServiceLocator.sessionLost.collect {
            enrolled = ServiceLocator.repository.isEnrolled
            navController.navigate(if (enrolled) Routes.DOORS else Routes.ENROLL) {
                popUpTo(0)
            }
        }
    }

    NavHost(
        navController = navController,
        startDestination = if (enrolled) Routes.DOORS else Routes.ENROLL,
    ) {
        composable(Routes.ENROLL) {
            EnrollmentScreen(
                onEnrolled = {
                    enrolled = true
                    navController.navigate(Routes.DOORS) { popUpTo(0) }
                }
            )
        }
        composable(Routes.DOORS) {
            DoorListScreen(
                activity = activity,
                onOpenHistory = { navController.navigate(Routes.HISTORY) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.HISTORY) {
            HistoryScreen(onBack = { navController.popBackStack() })
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
                onBack = { navController.popBackStack() },
                onForgotten = {
                    enrolled = false
                    navController.navigate(Routes.ENROLL) { popUpTo(0) }
                },
            )
        }
    }
}
