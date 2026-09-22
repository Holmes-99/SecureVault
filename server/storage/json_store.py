import json
from pathlib import Path


def save_json(file_path, data):
    #convert the path
    path = Path(file_path)

    #create the folder if it not exist
    path.parent.mkdir(parents=True, exist_ok=True)

    #save the data in readable form
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def load_json(file_path, default=None):
    path = Path(file_path)

    if not path.exists():
        return default

    #read and return saved data
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)