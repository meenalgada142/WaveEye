import os
import json
import string
from datetime import datetime

BASE_DIR = "uploaded_vcds"
MAX_UPLOADS_PER_USER = 100

def ensure_user_folder(user_id: int):
    user_folder = os.path.join(BASE_DIR, f"user{user_id}")
    os.makedirs(user_folder, exist_ok=True)

    log_path = os.path.join(user_folder, "data_upload_log.json")
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            json.dump({"uploads": []}, f, indent=4)

    return user_folder, log_path


def get_next_file_label(user_log):
    count = len(user_log["uploads"])
    letters = string.ascii_uppercase
    label = ""

    while True:
        label = letters[count % 26] + label
        count = count // 26 - 1
        if count < 0:
            break

    return label

import shutil

def save_vcd_file(user_id: int, uploaded_filename: str, upload_source_path: str):
    user_folder, log_path = ensure_user_folder(user_id)

    with open(log_path, "r") as f:
        user_log = json.load(f)

    if len(user_log["uploads"]) >= MAX_UPLOADS_PER_USER:
        raise Exception(f"Upload limit reached for user{user_id}")

    next_label = get_next_file_label(user_log)
    new_filename = f"user{user_id}{next_label}.vcd"
    dest_path = os.path.join(user_folder, new_filename)

    # FIX: Copy instead of replace (replace deletes original)
    shutil.copy2(upload_source_path, dest_path)

    entry = {
        "upload_number": len(user_log["uploads"]) + 1,
        "original_filename": uploaded_filename,
        "saved_filename": new_filename,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "waveform_json": None
    }

    user_log["uploads"].append(entry)

    with open(log_path, "w") as f:
        json.dump(user_log, f, indent=4)

    print(f"Saved {uploaded_filename} as {new_filename}")
    return dest_path, log_path



def update_json_path_in_log(user_id: int, vcd_filename: str, json_path: str):
    _, log_path = ensure_user_folder(user_id)
    with open(log_path, "r") as f:
        user_log = json.load(f)

    for entry in user_log["uploads"]:
        if entry["saved_filename"] == vcd_filename:
            entry["waveform_json"] = json_path
            break

    with open(log_path, "w") as f:
        json.dump(user_log, f, indent=4)


def get_or_create_user():
    os.makedirs(BASE_DIR, exist_ok=True)
    registry_path = os.path.join(BASE_DIR, "user_registry.json")

    if not os.path.exists(registry_path):
        with open(registry_path, "w") as f:
            json.dump({"next_user_id": 1}, f, indent=4)

    with open(registry_path, "r") as f:
        registry = json.load(f)

    user_id = registry["next_user_id"]
    registry["next_user_id"] += 1

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=4)

    return user_id
