import os
import shutil

def collect_logs():
    log_path = "C:/Windows/System32/winevt/Logs/"
    dest_path = "./logs"

    if not os.path.exists(dest_path):
        os.makedirs(dest_path)

    for file in os.listdir(log_path):
        if file.endswith(".evtx"):
            shutil.copy(os.path.join(log_path, file), dest_path)

    print(f"Logs collected and saved in {dest_path}")

if __name__ == "__main__":
    collect_logs()
