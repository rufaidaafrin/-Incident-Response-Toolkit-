import os

def analyze_memory(dump_file):
    os.system(f"volatility3 -f {dump_file} windows.pslist")

if __name__ == "__main__":
    dump_file = input("Enter memory dump file path: ")
    analyze_memory(dump_file)
