from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    device_id: str
    device_type: str
    topics_publish: tuple
    topic_subscribe: tuple
    publish_interval_range: tuple
    payload_size_range: tuple
    mac: str


PROFILES = (
    DeviceProfile(
        device_id="esp32_temp_01",
        device_type="temp_sensor",
        topics_publish=("lab/room1/temperature",),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(9.0, 11.0),
        payload_size_range=(40, 60),
        mac="AA:BB:CC:11:22:33",
    ),
    DeviceProfile(
        device_id="esp32_motion_01",
        device_type="motion_sensor",
        topics_publish=("lab/room1/motion",),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(0.5, 300.0),
        payload_size_range=(20, 40),
        mac="AA:BB:CC:44:55:66",
    ),
    DeviceProfile(
        device_id="esp32_plug_01",
        device_type="smart_plug",
        topics_publish=("lab/room1/power",),
        topic_subscribe=("lab/room1/cmd",),
        publish_interval_range=(14.0, 16.0),
        payload_size_range=(60, 90),
        mac="AA:BB:CC:77:88:99",
    ),
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
