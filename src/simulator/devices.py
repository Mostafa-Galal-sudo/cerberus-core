"""Device profiles for the CERBERUS simulated IoT testbed (Checkpoint 1, task C1-T04).

Each profile defines the *normal* behavior of one device class. The differences
between profiles (publish cadence, payload size) are the behavioral-fingerprint
signal that the Checkpoint-2 detection engine learns — keep the profiles
distinct, never homogenize them.

Firmware for the real testbed (Checkpoint 4) must mirror these profiles so the
detection engine behaves identically on simulated and real traffic.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    device_id: str
    device_type: str
    topics_publish: tuple[str, ...]
    topic_subscribe: tuple[str, ...]
    publish_interval_range: tuple[float, float]  # seconds, uniform jitter per publish
    payload_size_range: tuple[int, int]          # target serialized size, bytes
    mac: str

    @property
    def mean_publish_interval(self) -> float:
        return sum(self.publish_interval_range) / 2


DEVICE_PROFILES: tuple[DeviceProfile, ...] = (
    # Periodic sensor: tight, metronome-like cadence.
    DeviceProfile(
        device_id="esp32_temp_01",
        device_type="temp_sensor",
        topics_publish=("lab/room1/temperature",),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(9.0, 11.0),
        payload_size_range=(40, 60),
        mac="AA:BB:CC:11:22:33",
    ),
    # Event-driven sensor: mostly silent, bursts when something happens.
    DeviceProfile(
        device_id="esp32_motion_01",
        device_type="motion_sensor",
        topics_publish=("lab/room1/motion",),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(0.5, 300.0),
        payload_size_range=(20, 40),
        mac="AA:BB:CC:44:55:66",
    ),
    # Power telemetry: regular but with larger payloads.
    DeviceProfile(
        device_id="esp32_plug_01",
        device_type="smart_plug",
        topics_publish=("lab/room1/power",),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(14.0, 16.0),
        payload_size_range=(60, 90),
        mac="AA:BB:CC:77:88:99",
    ),
    # Coordinator node: slow heartbeat, biggest payloads, two topics.
    DeviceProfile(
        device_id="esp32_ctrl_01",
        device_type="controller",
        topics_publish=("lab/room1/status", "lab/room1/health"),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(30.0, 90.0),
        payload_size_range=(100, 150),
        mac="AA:BB:CC:99:AA:BB",
    ),
)
