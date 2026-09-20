package com.evtimov.doors.ui.screens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.evtimov.doors.di.ServiceLocator
import com.evtimov.doors.domain.Door
import com.evtimov.doors.domain.UnlockResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DoorListState(
    val loading: Boolean = true,
    val doors: List<Door> = emptyList(),
    val nearbyBeacon: Boolean = false,
    val offline: Boolean = false,
    val unlockingDoorId: String? = null,
    val lastResult: UnlockResult? = null,
)

class DoorListViewModel : ViewModel() {

    private val repository = ServiceLocator.repository
    private val scanner = ServiceLocator.beaconScanner

    private val _state = MutableStateFlow(DoorListState())
    val state: StateFlow<DoorListState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            scanner.latest.collect {
                _state.value = _state.value.copy(nearbyBeacon = scanner.freshest() != null)
            }
        }
        refresh()
    }

    fun startScanning() = scanner.start()

    fun stopScanning() = scanner.stop()

    fun refresh() {
        viewModelScope.launch {
            _state.value = _state.value.copy(loading = true)
            repository.doors().fold(
                onSuccess = { doors ->
                    _state.value = _state.value.copy(
                        loading = false, doors = doors, offline = false,
                    )
                },
                onFailure = {
                    // Offline is a state the app shows honestly, not an empty
                    // list that looks like "you have no doors".
                    _state.value = _state.value.copy(loading = false, offline = true)
                },
            )
        }
    }

    /**
     * [authenticate] is the biometric prompt. It runs *before* the request,
     * because it is what makes the Keystore key usable - not a confirmation
     * step that could be skipped without consequence.
     */
    fun unlock(doorId: String, authenticate: suspend () -> Boolean) {
        if (_state.value.unlockingDoorId != null) return

        viewModelScope.launch {
            _state.value = _state.value.copy(unlockingDoorId = doorId, lastResult = null)

            if (!authenticate()) {
                _state.value = _state.value.copy(
                    unlockingDoorId = null, lastResult = UnlockResult.BiometricRefused,
                )
                return@launch
            }

            val result = repository.unlock(doorId)
            _state.value = _state.value.copy(unlockingDoorId = null, lastResult = result)
        }
    }

    fun clearResult() {
        _state.value = _state.value.copy(lastResult = null)
    }

    override fun onCleared() {
        scanner.stop()
        super.onCleared()
    }
}
