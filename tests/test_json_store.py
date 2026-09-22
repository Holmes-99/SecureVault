from server.storage.json_store import load_json, save_json


def test_save_and_load_json(tmp_path):
    #use temp file while testing
    file_path = tmp_path / "data.json"
    original_data = {
        "username": "lara",
        "files": ["notes.txt", "report.pdf"]
    }

    save_json(file_path, original_data)

    assert file_path.exists()
    assert load_json(file_path) == original_data


def test_load_missing_file_returns_default(tmp_path):
    file_path = tmp_path / "missing.json"

    result = load_json(file_path, default={})

    assert result == {}


def test_save_creates_parent_directories(tmp_path):
    file_path = tmp_path / "data" / "users.json"

    save_json(file_path, {"users": []})

    #nested folder created automatically
    assert load_json(file_path) == {"users": []}