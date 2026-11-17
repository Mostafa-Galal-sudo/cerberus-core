Set-Location $PSScriptRoot\..
.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'.'); import json; from src.storage import db; c=db.open_db('data/lab/lab_traffic.db'); print(json.dumps(db.summarize(c), indent=2))"
