package com.evtimov.doors.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.viewmodel.compose.viewModel
import com.evtimov.doors.R
import com.evtimov.doors.data.crypto.BiometricGate
import com.evtimov.doors.domain.Door
import com.evtimov.doors.domain.UnlockResult
import com.evtimov.doors.ui.components.MessageCard
import com.evtimov.doors.ui.components.StatusRow
import com.evtimov.doors.ui.components.Tone

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DoorListScreen(
    activity: FragmentActivity,
    onOpenHistory: () -> Unit,
    onOpenSettings: () -> Unit,
    viewModel: DoorListViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    val gate = remember { BiometricGate(activity) }
    val lifecycleOwner = LocalLifecycleOwner.current

    // Scanning only while this screen is in front. A permanently scanning app
    // is a battery problem and a privacy one, and neither is necessary: the
    // beacon only matters at the moment someone wants to open a door.
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> {
                    viewModel.startScanning()
                    viewModel.refresh()
                }
                Lifecycle.Event.ON_PAUSE -> viewModel.stopScanning()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.doors_title)) },
                actions = {
                    IconButton(onClick = onOpenHistory) {
                        Icon(Icons.Default.History, contentDescription = stringResource(R.string.history_title))
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, contentDescription = stringResource(R.string.settings_title))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            state.lastResult?.let { result ->
                ResultBanner(result)
                Spacer(Modifier.height(12.dp))
            }

            when {
                state.offline -> MessageCard(
                    title = stringResource(R.string.error_offline),
                    body = "The app cannot reach the server. Doors cannot be " +
                        "opened while this is the case - nothing is cached and " +
                        "nothing opens without the server's signature.",
                    tone = Tone.Error,
                )

                state.loading && state.doors.isEmpty() ->
                    CircularProgressIndicator(Modifier.padding(32.dp))

                state.doors.isEmpty() -> MessageCard(
                    title = stringResource(R.string.doors_empty),
                    body = "Ask your administrator to grant you a door.",
                )
            }

            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(state.doors, key = { it.id }) { door ->
                    DoorCard(
                        door = door,
                        nearby = state.nearbyBeacon,
                        busy = state.unlockingDoorId == door.id,
                        onUnlock = {
                            viewModel.unlock(door.id) {
                                gate.authenticate(
                                    title = activity.getString(R.string.biometric_title),
                                    subtitle = activity.getString(R.string.biometric_subtitle),
                                    cancel = activity.getString(R.string.biometric_cancel),
                                )
                            }
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun DoorCard(door: Door, nearby: Boolean, busy: Boolean, onUnlock: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(door.name, style = MaterialTheme.typography.titleLarge)
            door.location?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(8.dp))
            Text(door.window, style = MaterialTheme.typography.bodySmall)

            Spacer(Modifier.height(12.dp))

            // Both conditions are shown separately, because they have
            // different remedies: one means walk closer, the other means call
            // someone.
            StatusRow(
                color = if (door.controllerOnline) Color(0xFF2E7D32) else Color(0xFFB3261E),
                text = if (door.controllerOnline) "Controller online"
                       else stringResource(R.string.doors_offline),
            )
            Spacer(Modifier.height(4.dp))
            StatusRow(
                color = if (nearby) Color(0xFF2E7D32) else Color(0xFF9E9E9E),
                text = if (nearby) "In range" else stringResource(R.string.doors_out_of_range),
            )

            Spacer(Modifier.height(16.dp))

            Button(
                onClick = onUnlock,
                enabled = !busy && door.controllerOnline && nearby,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.padding(horizontal = 6.dp))
                        Text(stringResource(R.string.unlock_opening))
                    }
                } else {
                    Text(stringResource(R.string.unlock_action))
                }
            }
        }
    }
}

@Composable
private fun ResultBanner(result: UnlockResult) {
    when (result) {
        is UnlockResult.Opened -> MessageCard(
            stringResource(R.string.unlock_opened),
            "The controller confirmed it opened the door.",
        )
        UnlockResult.Denied -> MessageCard(
            "Not allowed", stringResource(R.string.error_denied), Tone.Warning,
        )
        UnlockResult.NotPresent -> MessageCard(
            "Too far away", stringResource(R.string.error_not_present), Tone.Warning,
        )
        UnlockResult.ControllerOffline -> MessageCard(
            "Door unreachable", stringResource(R.string.error_controller_offline), Tone.Error,
        )
        UnlockResult.RateLimited -> MessageCard(
            "Slow down", stringResource(R.string.error_rate_limited), Tone.Warning,
        )
        UnlockResult.Failed -> MessageCard(
            "Not confirmed", stringResource(R.string.error_failed), Tone.Error,
        )
        UnlockResult.SessionLost -> MessageCard(
            "Signed out", stringResource(R.string.error_session), Tone.Error,
        )
        UnlockResult.Offline -> MessageCard(
            "No connection", stringResource(R.string.error_offline), Tone.Error,
        )
        UnlockResult.BiometricRefused -> MessageCard(
            "Cancelled", "Nothing was sent.", Tone.Neutral,
        )
    }
}
