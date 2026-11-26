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


# Core lab profiles (kept for backward compatibility with C1/C2/C3 tests)
_CORE_PROFILES = (
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

# (device_type, slug, hardware, interval_range, payload_range, qos, offline_rate)
_DEVICE_SPECS = {
    "IP Camera": ("camera", "cam", "RTSP/MQTT Edge Camera", (5.0, 10.0), (155, 220), 0, 0.5),
    "Smart Lock": ("door", "lock", "Smart Deadbolt Controller", (60.0, 600.0), (155, 195), 1, 0.3),
    "Badge Reader": ("access", "badge", "NFC/Wiegand Badge Reader", (10.0, 120.0), (155, 195), 1, 0.4),
    "RFID Reader": ("access", "rfid", "UHF RFID Gate Reader", (5.0, 60.0), (155, 195), 1, 0.5),
    "Motion Sensor": ("motion", "motion", "PIR Motion Sensor", (1.0, 180.0), (155, 190), 1, 0.8),
    "Door Sensor": ("door", "door", "Magnetic Reed Door Sensor", (60.0, 900.0), (155, 190), 1, 0.4),
    "Smart Lighting": ("plug", "light", "Dimmable Relay Controller", (15.0, 30.0), (155, 200), 0, 0.8),
    "Access Point": ("network", "ap", "Industrial Wi-Fi AP", (10.0, 20.0), (155, 205), 0, 0.2),
    "HVAC Controller": ("plug", "hvac", "Modbus/MQTT HVAC Relay", (12.0, 20.0), (155, 205), 0, 0.4),
    "Temperature Sensor": ("climate", "temp", "Industrial Temp Probe", (8.0, 12.0), (155, 215), 0, 0.6),
    "Humidity Sensor": ("climate", "humid", "Industrial RH Probe", (8.0, 12.0), (155, 215), 0, 0.6),
    "Gateway": ("network", "gw", "MQTT Edge Gateway", (5.0, 10.0), (155, 215), 1, 0.1),
    "Industrial Switch": ("network", "sw", "Managed L2/L3 Switch", (10.0, 15.0), (155, 210), 0, 0.1),
    "Smoke Detector": ("safety", "smoke", "Optical Smoke Detector", (20.0, 60.0), (155, 195), 1, 0.2),
    "Smart Meter": ("plug", "meter", "3-Phase Power Meter", (10.0, 15.0), (155, 205), 0, 0.3),
    "HMI Panel": ("hmi", "hmi", "Operator HMI Touch Panel", (5.0, 15.0), (155, 210), 1, 0.2),
    "PLC": ("plc", "plc", "Industrial PLC Controller", (2.0, 6.0), (155, 215), 1, 0.1),
    "Robotic Arm": ("motor", "arm", "6-Axis Servo Robotic Arm", (3.0, 8.0), (155, 215), 0, 0.3),
    "Conveyor Controller": ("motor", "conv", "VFD Conveyor Drive", (4.0, 10.0), (155, 210), 0, 0.4),
    "Vibration Sensor": ("sensor", "vib", "Tri-Axial MEMS Accelerometer", (5.0, 12.0), (155, 205), 0, 0.5),
    "Pressure Sensor": ("sensor", "press", "Piezo Pressure Transmitter", (5.0, 12.0), (155, 200), 0, 0.4),
    "Gas Sensor": ("safety", "gas", "Electrochemical Gas Detector", (10.0, 20.0), (155, 200), 1, 0.3),
    "Smart Valve": ("plug", "valve", "Motorized Solenoid Valve", (15.0, 45.0), (155, 200), 1, 0.3),
    "Flow Meter": ("sensor", "flow", "Ultrasonic Flow Meter", (8.0, 15.0), (155, 200), 0, 0.4),
}

FACILITY_ROOMS: dict[str, tuple[str, ...]] = {
    "main_gate": ("IP Camera", "Smart Lock", "Badge Reader", "RFID Reader", "Motion Sensor"),
    "reception": ("IP Camera", "Badge Reader", "Door Sensor", "Smart Lighting", "Access Point"),
    "admin_offices": ("Access Point", "HVAC Controller", "Smart Lighting", "Door Sensor", "Temperature Sensor"),
    "server_room": (
        "Gateway", "Industrial Switch", "IP Camera", "Temperature Sensor",
        "Humidity Sensor", "Smoke Detector", "Smart Lock", "Smart Meter", "HVAC Controller",
    ),
    "control_room": ("HMI Panel", "Gateway", "IP Camera", "Access Point", "Door Sensor", "Smart Lock"),
    "raw_materials_storage": (
        "IP Camera", "Temperature Sensor", "Humidity Sensor", "RFID Reader", "Door Sensor", "Smoke Detector",
    ),
    "production_line_1": (
        "PLC", "Robotic Arm", "Conveyor Controller", "HMI Panel", "Vibration Sensor",
        "Temperature Sensor", "Pressure Sensor", "Motion Sensor", "IP Camera",
    ),
    "production_line_2": (
        "PLC", "Robotic Arm", "Conveyor Controller", "HMI Panel", "Vibration Sensor",
        "Temperature Sensor", "Pressure Sensor", "Motion Sensor", "IP Camera",
    ),
    "assembly_hall": (
        "PLC", "Robotic Arm", "HMI Panel", "Vibration Sensor", "Motion Sensor", "IP Camera", "Industrial Switch",
    ),
    "packaging_area": ("PLC", "Conveyor Controller", "HMI Panel", "Motion Sensor", "RFID Reader", "IP Camera"),
    "quality_lab": (
        "HMI Panel", "Temperature Sensor", "Humidity Sensor", "Gas Sensor", "Smart Lock", "IP Camera", "Access Point",
    ),
    "finished_goods_warehouse": (
        "IP Camera", "RFID Reader", "Temperature Sensor", "Humidity Sensor",
        "Smoke Detector", "Door Sensor", "Smart Lighting",
    ),
    "loading_dock": ("IP Camera", "RFID Reader", "Smart Lock", "Motion Sensor", "Door Sensor", "Badge Reader"),
    "boiler_room": (
        "Smart Valve", "Pressure Sensor", "Temperature Sensor", "Flow Meter",
        "Gas Sensor", "Smoke Detector", "Vibration Sensor",
    ),
    "electrical_room": (
        "Smart Meter", "Temperature Sensor", "Smoke Detector", "Smart Lock", "Door Sensor", "HVAC Controller",
    ),
    "parking": ("IP Camera", "Motion Sensor", "Smart Lighting", "Smart Lock", "Badge Reader"),
}


def _build_facility_profiles() -> tuple[DeviceProfile, ...]:
    profiles: list[DeviceProfile] = list(_CORE_PROFILES)
    idx = 1
    for room, devices in FACILITY_ROOMS.items():
        for label in devices:
            dev_type, slug, hw, interval, psize, qos, offline = _DEVICE_SPECS[label]
            dev_id = f"{room}_{slug}"
            octet3 = 10 + (idx // 250)
            octet4 = 1 + (idx % 250)
            mac = f"A0:CE:00:{(idx >> 16) & 0xFF:02X}:{(idx >> 8) & 0xFF:02X}:{idx & 0xFF:02X}"
            profiles.append(
                DeviceProfile(
                    device_id=dev_id,
                    device_type=dev_type,
                    hardware=hw,
                    room=room,
                    topics_publish=(f"lab/{room}/{slug}",),
                    topic_subscribe=(f"lab/{room}/cmd",),
                    status_topic=f"lab/status/{dev_id}",
                    publish_interval_range=interval,
                    payload_size_range=psize,
                    mac=mac,
                    ip=f"192.168.{octet3}.{octet4}",
                    qos=qos,
                    offline_rate_per_hour=offline,
                )
            )
            idx += 1
    return tuple(profiles)


PROFILES = _build_facility_profiles()
