# CERBERUS (`cerberus-core`) — Study Guide (C1 & C2)

الدليل ده بيشرح المشروع خطوة بخطوة (`t0x` by `t0x`) بالعربي المصري البسيط مع المصطلحات التقنية بالإنجليزي، وبيغطي بس الكود والاختبارات والتقارير اللي في `src/` و`tests/` و`docs/` و`results/`.

---

## الفكرة العامة للمشروع

هدف **CERBERUS** هو حماية شبكات الـ IoT (زي أجهزة ESP32) عن طريق 5 طبقات متوصلة ببعض (`docs/ARCHITECTURE.md`):
1. **Testbed / Attack**: أجهزة ESP32 (أو simulator حالياً) بتبعت رسائل MQTT على Mosquitto broker، ومعاها attack generator.
2. **Detection**: محرك كشف هجين (`HybridDetector`) بيجمع بين Rules + ML + Behavioral Fingerprinting.
3. **Defense**: LLM agent (Groq) بيحقق في الـ alerts ويبني timeline للحادثة *(Checkpoint 3)*.
4. **Policy & Response**: بوابة صلاحيات واحدة (`src/policy/`) بتمنع أي تنفيذ عشوائي وبتعزل الجهاز المهاجم *(Checkpoint 3)*.
5. **Presentation**: SOC dashboard + تنبيهات *(Checkpoint 3+)*.

---

## Checkpoint 1 — Foundation & Data Pipeline

الهدف هنا كان بناء الأساس: محاكاة أجهزة حقيقية، تخزين الداتا، وفهم dataset الـ CICIoT2023.

### `C1-T01` — Repo Scaffold & `.gitignore`
- **إيه اللي اتعمل؟** تقسيم الفولدرات (`src/`, `tests/`, `docs/`, `results/`, `data/`, `firmware/`) وإعداد `.gitignore`.
- **ليه مهم؟** عشان الـ `.venv/` والـ datasets الضخمة (`data/raw/`, `data/lab/`, `*.db`, `*.pcap`) والـ secrets (`.env`) ما تترفعش على Git بالغلط.

### `C1-T02` — `README.md` & `docs/ARCHITECTURE.md`
- **إيه اللي اتعمل؟** توثيق الـ 5-layer pipeline والـ 5 **Invariants** الأساسية:
  1. أي إجراء خطير لازم يعدي من `src/policy/` (No bypass).
  2. الـ LLM يقترح، والـ Policy هي اللي تقرر.
  3. لو الـ LLM API وقع، النظام يكمل بالـ rules من غير ما يقع (Deterministic fallback).
  4. كل الـ timestamps بتتخزن **UTC ISO8601**.
  5. الـ Simulator profiles تطابق الـ ESP32 firmware مستقبلاً.

### `C1-T03` — Local Mosquitto Broker (`mosquitto.conf`)
- **إيه اللي اتعمل؟** تشغيل Mosquitto على port `1883` بإعدادات `allow_anonymous true` في `mosquitto.conf` عشان الأجهزة الافتراضية تتواصل محلياً.

### `C1-T04` — Device Profiles & Sensors (`src/simulator/devices.py`, `sensors.py`)
- **إيه اللي اتعمل؟**
  - في `devices.py`: عملنا `DeviceProfile` لـ 5 أجهزة ESP32 مختلفة:
    - `esp32_temp_01` و`esp32_temp_02` (حرارة ورطوبة — كل 9–13 ثانية).
    - `esp32_motion_01` (حركة PIR — event-driven).
    - `esp32_plug_01` (فيشة ذكية + قياس وات — كل 14–16 ثانية، وبتستقبل أمر `toggle`).
    - `esp32_door_01` (حساس باب — event-driven).
  - في `sensors.py`: محاكاة واقعية لقراءات السنسور (`ClimateSensor` بـ random walk و1% dropout للرطوبة، `PowerSensor` بـ `toggle()`، و`RssiWalk` و`HeapWalk`).
- **ليه اختلاف الـ intervals والأحجام مهم؟** لأن الاختلافات دي هي اللي بتكوّن البصمة السلوكية (**Behavioral Fingerprint**) لكل جهاز في C2.

### `C1-T05` — Traffic Generator (`src/simulator/traffic_gen.py`)
- **إيه اللي اتعمل؟** سكريبت `generate()` بيتصل بـ Mosquitto عبر `paho-mqtt`، يشغل loop كل `0.05` ثانية (`LOOP_DT`)، يبعت رسائل الأجهزة، يحاكي انقطاع الاتصال (`go_offline` / `come_online` بـ retained status)، ويسمع أوامر `lab/+/cmd`.
- **مشكلة واتحلت**: كان فيه padding لحجم الـ payload ممكن يقص الـ JSON في النص؛ اتعدل في `finish()` بحيث يضيف `"pad"` فقط لما المساحة المتاحة `>= 9` bytes.

### `C1-T06` — SQLite Storage (`src/storage/db.py`)
- **إيه اللي اتعمل؟** جدول `mqtt_events` في SQLite بوضع `WAL` مع 3 indexes (`ts_utc`, `topic`, `device_id`).
- **تفصيلة مهمة**: لأن `paho-mqtt` بيشغل callbacks في thread تاني، استخدمنا `check_same_thread=False` مع `_WRITE_LOCK` جوه `save_event()` لمنع تعارض الكتابة.

### `C1-T07` — Simulator & Storage Tests (`tests/test_traffic_gen.py`)
- **إيه اللي اتعمل؟** 10 unit tests بتتأكد من: إنشاء الجدول والـ indexes، حفظ واسترجاع الأحداث، التزام أحجام الـ payload بحدود كل `DeviceProfile`، سلوك السنسورز، و`db.summarize()`.

### `C1-T08` — CICIoT2023 Dataset Download (`data/raw/ciciot2023/CSV/`)
- **إيه اللي اتعمل؟** تحميل الـ dataset (310 ملف CSV / 9.66 GB مقيسين، ~46.7 مليون صف) متقسمة لفولدرات حسب نوع الهجوم + `Benign_Final/`.

### `C1-T09` — Exploratory Data Analysis (`src/notebooks/01_ciciot_eda.ipynb`)
- **إيه اللي اتعمل؟** Notebook من 8 أقسام كشف حقائق مهمة جداً قبل كتابة موديلات الكشف:
  - فيه **39 numeric feature**، والملفات مفيهاش عمود `label` — اسم الفولدر هو الـ label.
  - نسبة الـ `Benign` فقط **2.35%** من الـ 46.7M صف (Class imbalance شديد).
  - هجمات الـ Flooding (`DDoS` + `DoS` + `Mirai`) حوالي 44.5M صف، عكس `Recon` و`Web` و`BruteForce` اللي حجمهم صغير جداً وأصعب في الكشف بالـ rules لوحدها.

### `C1-T10` — Live Demo Launcher (`demo.ps1`)
- **إيه اللي اتعمل؟** سكريبت PowerShell بيفتح 4 نوافذ بضغطة واحدة: (1) Mosquitto broker، (2) `mosquitto_sub` لمراقبة `lab/#`، (3) `traffic_gen.py`، (4) نافذة تحكم تفاعلية تعمل `toggle` للفيشة أو تطبع `db.summarize()`.

---

## Checkpoint 2 — Detection Engine v1 + Benchmark

الهدف هنا بناء محرك الكشف واختباره على CICIoT2023 بدون Data Leakage، وبعدين التأكد إنه شغال على بيانات الـ MQTT Lab.

### `C2-T01` — Sliding-Window Features (`src/detection/features.py`)
- **إيه اللي اتعمل؟** دالة `device_windows()` بتجمع رسائل كل جهاز من `mqtt_events` في نوافذ زمنية (`window_sec=60`, `step_sec=30`) وتطلع **14 feature** (`FEATURE_NAMES`):
  - معدل الأحداث (`event_count`, `rate_per_sec`).
  - إحصائيات الحجم (`payload_mean`, `payload_std`, `payload_max`, `payload_min`, `size_diversity`).
  - الفواصل الزمنية (`gap_mean`, `gap_std`, `gap_cv`).
  - السلوك (`topic_count`, `topic_entropy`, `qos_mean`, `publish_share`).
- **تعديلات قفلت ثغرات لاحقاً**:
  - النافذة الأخيرة الناقصة (trailing partial window) كانت بتقسم على `window_sec` الكامل (60s) وده كان بيقلل `rate_per_sec`؛ اتصلحت بحيث تقسم على المدة الفعلية (`end - start`).
  - اتضافت `topic_entropy` (Shannon entropy لتوزيع الـ topics).

### `C2-T02` — CICIoT2023 Loader (`src/detection/dataset.py`)
- **إيه اللي اتعمل؟**
  - `category_of()`: بتحول أسماء الـ 34 فولدر لـ 8 فئات (`Benign`, `DDoS`, `DoS`, `Mirai`, `Recon`, `Spoofing`, `Web`, `BruteForce`).
  - `load_sample()`: بتاخد عينة عشوائية بـ `seed=0` (`df.sample(n=rows_per_file, random_state=seed)`) بدل أول N صفوف (لأن أول الصفوف في كل ملف كان فيها capture-start bias)، وبتشيل الأعمدة الثابتة (`drop_constant_features()`).
  - `split_by_file()`: بتقسم Train/Test على مستوى **الملف** مش الصف، عشان نفس الـ capture ما يظهرش في الناحيتين.

### `C2-T03` — Rules Engine (`src/detection/rules_engine.py`)
- **إيه اللي اتعمل؟** `RuleEngine` بيدعم مجموعتين من القواعد:
  - `CICIOT_RULES` (8 rules، زي `rate_spike`, `interarrival_collapse`, `syn_saturation`, `icmp_share`).
  - `MQTT_RULES` (6 rules، زي `rate_spike`, `gap_mean`, `payload_bloat`, `topic_burst`).
- **إزاي بيتدرب؟** بيتعلم الـ thresholds أوتوماتيك من الـ `Benign` traffic بس (عند `high_q=0.999` و`low_q=0.001`) من غير أرقام hardcoded.

### `C2-T04` — Unsupervised ML (`src/detection/ml_model.py`)
- **إيه اللي اتعمل؟** `AnomalyModel` مبني على `IsolationForest` متدرب على `Benign` بس.
- **المعالجة (`clean`)**: تعويض `±inf`/`NaN` بالـ median، وبعدين Robust Scaling باستخدام `(x - median) / IQR` مع clipping على `[-5.0, 5.0]` عشان الـ outliers ما تبوظش التدريب.

### `C2-T05` — Behavioral Fingerprinting (`src/detection/fingerprint.py`)
- **إيه اللي اتعمل؟** `DeviceFingerprint` بيبني لكل `device_id` profile خاص بيه من `FEATURE_NAMES` (median + MAD).
- لو جهاز عدد نوافذه أقل من `min_windows=5` أو جهاز جديد غريب، بيرجع للـ `global_` baseline، و`known(device_id)` بتقولنا هل الجهاز متعرف قبل كده ولا لأ.
- **مشكلة واتحلت**: لما `MAD == 0` في القيم الصحيحة الثابتة نسبياً (زي `event_count`), الكود القديم كان بينط فوراً لـ `0.01 * median` فكان أي تغيير بسيط يضرب `z = 20.0` ويرفع الـ threshold لـ `20.0`. اتصلح بإنه يجرب `std` الأول قبل الـ `floor`.

### `C2-T06` — Deviation Baseline & Hybrid Detector (`src/detection/baseline.py`, `hybrid.py`)
- **إيه اللي اتعمل؟**
  - `DeviationBaseline`: النسخة الـ population-level من البصمة السلوكية (median + MAD z-scores على كل الـ features، مقصوصة عند `SCORE_CLIP=20.0`).
    - *مشكلة واتحلت*: `drivers()` كانت بترتب على القيم المقصوصة فلو كذا feature وصلوا `20.0` كانت بتختار الأعمدة الأخيرة بالترتيب وتسيب `'Rate'`. اتصلحت بالترتيب على القيم قبل القص.
  - `HybridDetector`: بيجمع التلاتة مع بعض:
    - Fast path: `RuleEngine` (`hits >= 1`).
    - Slow path: `DeviationBaseline`.
    - Identity/Behavior path: `DeviceFingerprint` + كشف تلقائي للأجهزة المجهولة (`unknown_device:<id>`).
    - بيطلع `alert`, `severity` (`high`/`medium`), `confidence` (بأوزان `0.45 / 0.35 / 0.20`), و`explanation` مقروء.

### `C2-T07` — Benchmark Harness (`src/evaluation/benchmark.py`)
- **إيه اللي اتعمل؟** مقارنة عادلة بين 5 detectors (`rules`, `rules_strict`, `iforest`, `baseline`, `hybrid`) بنفس الـ pipeline وتقسيم `partition()` على مستوى الملفات (2 ملفات benign للتدريب، 2 ملفات benign + كل الهجمات للاختبار)، مع حساب الـ Precision/Recall/F1/FPR وطباعة 2×2 **Confusion Matrices**.

### `C2-T08` — CICIoT2023 Benchmark Results (`results/benchmark_ciciot_v1.md`)
- **النتائج النهائية (بعد الـ random sampling)**:
  - `hybrid`: Precision `0.956`, Recall `0.957`, F1 **`0.956`**, FPR `0.041`.
  - `rules`: F1 **`0.958`**, FPR `0.036`.
  - `baseline`: F1 **`0.926`**, FPR **`0.005`** (أقل false positives بين نماذج الـ anomaly).
  - `iforest`: F1 `0.604`, Recall `0.440`, FPR `0.016`.
  - `rules_strict` (2+ hits): Precision `0.996`, FPR `0.001`, بس Recall نزل لـ `0.282`.
- **الخلاصة العلمية**: الـ `rules` والـ `hybrid` ممتازين في الـ Flooding (`DDoS`/`DoS`/`Mirai` ~100% recall)، بينما الهجمات الهادئة (`Recon` `0.230`, `Spoofing` `0.070`, `Web` `0.014`) لسه محتاجة ميزات flow/session أعمق أو سياق إضافي في المراحل الجاية.

### `C2-T09` — Live Anomaly Injection & Lab Check (`src/simulator/anomalies.py`, `src/evaluation/lab_check.py`, `tests/`)
- **إيه اللي اتعمل؟**
  - `anomalies.py`: حقن 3 هجمات MQTT حقيقية على Mosquitto (`flood`, `bloat`, `rogue`).
  - `lab_check.py`: بيشغل فحص synthetic (`run_lab_check()`) وكمان فحص على قاعدة بيانات حقيقية (`evaluate_db()` على `data/lab/lab_traffic.db` مع `traffic_gen.py` + `anomalies.py`).
  - `tests/`: تغطية كاملة بـ **71 unit & integration tests** عبر 12 ملف، من ضمنهم اختبارات الـ policy gates والـ agents والـ dashboard. النتيجة المتحققة **71/71 passed** موثقة في `results/TEST_RESULTS.md`.
