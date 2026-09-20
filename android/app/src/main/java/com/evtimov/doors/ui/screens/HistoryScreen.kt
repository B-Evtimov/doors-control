package com.evtimov.doors.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.evtimov.doors.R
import com.evtimov.doors.di.ServiceLocator
import com.evtimov.doors.domain.AccessRecord
import com.evtimov.doors.ui.components.MessageCard
import com.evtimov.doors.ui.components.Tone

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(onBack: () -> Unit) {
    var records by remember { mutableStateOf<List<AccessRecord>>(emptyList()) }
    var failed by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        ServiceLocator.repository.history().fold(
            onSuccess = { records = it },
            onFailure = { failed = true },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.history_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
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
            if (failed) {
                MessageCard(
                    stringResource(R.string.error_offline),
                    "Your history lives on the server and is not cached here.",
                    Tone.Error,
                )
            }

            // Only this user's own rows, filtered server side. There is no
            // parameter on the endpoint that widens the scope.
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(records, key = { it.seq }) { record ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp)) {
                            Text(
                                readableEvent(record.eventType),
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Text(
                                record.occurredAt.replace('T', ' ').take(19),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun readableEvent(eventType: String): String = when (eventType) {
    "door.unlock_confirmed" -> "Door opened"
    "door.unlock_granted" -> "Unlock approved"
    "door.unlock_denied" -> "Unlock refused"
    "door.unlock_failed" -> "Door did not confirm"
    else -> eventType
}
