from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    device_id: str
    device_type: str
    hardware: str
    room: str
    topics_publish: tuple
    topic_subscribe: tuple
    status_topic: str
    publish_interval_range: tuple
    payload_size_range: tuple
    mac: str
    ip: str
    qos: int
    offline_rate_per_hour: float


PROFILES = (
    DeviceProfile(
        device_id="esp32_temp_01",
        device_type="climate",
        hardware="ESP32-WROOM-32 + BME280",
        room="room1",
        topics_publish=("lab/room1/climate",),
        topic_subscribe=("lab/room1/cmd",),
        status_topic="lab/status/esp32_temp_01",
        publish_interval_range=(9.0, 11.0),
        payload_size_range=(170, 200),
        mac="24:0A:C4:11:22:33",
        ip="192.168.1.101",
        qos=0,
        offline_rate_per_hour=1.5,
    ),
    DeviceProfile(
        device_id="esp32_temp_02",
        device_type="climate",
        hardware="ESP32-WROOM-32 + DHT22",
        room="room2",
        topics_publish=("lab/room2/climate",),
        topic_subscribe=("lab/room2/cmd",),
        status_topic="lab/status/esp32_temp_02",
        publish_interval_range=(11.0, 13.0),
        payload_size_range=(170, 200),
        mac="24:6F:28:44:55:66",
        ip="192.168.1.102",
        qos=0,
        offline_rate_per_hour=2.5,
    ),
    DeviceProfile(
        device_id="esp32_motion_01",
        device_type="motion",
        hardware="ESP32-WROOM-32 + PIR HC-SR501",
        room="room1",
        topics_publish=("lab/room1/motion",),
        topic_subscribe=("lab/room1/cmd",),
        status_topic="lab/status/esp32_motion_01",
        publish_interval_range=(0.5, 300.0),
        payload_size_range=(160, 178),
        mac="30:AE:A4:77:88:99",
        ip="192.168.1.103",
        qos=1,
        offline_rate_per_hour=1.0,
    ),
    DeviceProfile(
        device_id="esp32_plug_01",
        device_type="plug",
        hardware="ESP32-WROOM-32 + relay + ACS712",
        room="room1",
        topics_publish=("lab/room1/power",),
        topic_subscribe=("lab/room1/cmd",),
        status_topic="lab/status/esp32_plug_01",
        publish_interval_range=(14.0, 16.0),
        payload_size_range=(165, 195),
        mac="A4:CF:12:AA:BB:CC",
        ip="192.168.1.104",
        qos=0,
        offline_rate_per_hour=1.5,
    ),
    DeviceProfile(
        device_id="esp32_door_01",
        device_type="door",
        hardware="ESP32-WROOM-32 + reed switch",
        room="garage",
        topics_publish=("lab/garage/door",),
        topic_subscribe=("lab/garage/cmd",),
        status_topic="lab/status/esp32_door_01",
        publish_interval_range=(300.0, 1800.0),
        payload_size_range=(160, 178),
        mac="24:D7:EB:DD:EE:FF",
        ip="192.168.1.105",
        qos=1,
        offline_rate_per_hour=0.5,
    ),
)
