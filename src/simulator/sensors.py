import random


class ClimateSensor:
    def __init__(self, base_temp, base_humid):
        self.base_temp = base_temp
        self.base_humid = base_humid
        self.temp = base_temp
        self.humid = base_humid

    def read(self):
        self.temp += random.gauss(0, 0.15) - (self.temp - self.base_temp) * 0.05
        self.humid += random.gauss(0, 0.6) - (self.humid - self.base_humid) * 0.05
        temp = round(self.temp, 2)
        humid = None if random.random() < 0.01 else round(self.humid, 2)
        return temp, humid


class PowerSensor:
    def __init__(self):
        self.on = random.random() < 0.6
        self.idle_w = 3.8

    def toggle(self):
        self.on = not self.on

    def read(self):
        if random.random() < 0.015:
            self.on = not self.on
        if self.on:
            watts = random.uniform(85.0, 135.0)
        else:
            watts = self.idle_w + random.uniform(0.0, 0.4)
        return round(watts, 1), ("on" if self.on else "off")


class MotorSensor:
    def __init__(self, base_rpm=1450):
        self.base_rpm = base_rpm
        self.running = random.random() < 0.7
        self.rpm = base_rpm if self.running else 0
        self.temp_c = 38.0

    def read(self):
        if random.random() < 0.02:
            self.running = not self.running
        if self.running:
            self.rpm = max(200, int(self.base_rpm + random.gauss(0, 35)))
            self.temp_c += random.gauss(0, 0.25) + (46.0 - self.temp_c) * 0.05
        else:
            self.rpm = 0
            self.temp_c += random.gauss(0, 0.15) + (26.0 - self.temp_c) * 0.05
        return self.rpm, round(self.temp_c, 1), ("running" if self.running else "idle")


class RssiWalk:
    def __init__(self):
        self.dbm = random.randint(-65, -45)

    def step(self):
        self.dbm += random.choice((-1, 0, 1))
        if self.dbm > -38:
            self.dbm -= 1
        if self.dbm < -82:
            self.dbm += 1
        return self.dbm


class HeapWalk:
    def __init__(self):
        self.free = random.randint(230_000, 280_000)

    def step(self):
        self.free += random.gauss(0, 800)
        if self.free < 180_000:
            self.free += random.uniform(30_000, 60_000)
        if self.free > 300_000:
            self.free -= random.uniform(10_000, 30_000)
        return int(self.free)
