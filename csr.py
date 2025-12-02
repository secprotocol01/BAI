#!/usr/bin/env python3
import sys
import re

def clean_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        cleaned_lines = []
        for line in lines:

            # 1) Odebrání "│   " na začátku
            line = re.sub(r"^│\s{1,3}", "", line)

            # 2) Odebrání "│" na konci + mezery před ním
            line = re.sub(r"\s*│\s*$", "", line)

            # 3) Odebrání samotného "│" na začátku bez mezery
            line = re.sub(r"^│", "", line)

            # 4) Odebrání samotného "│" na konci bez mezery
            line = re.sub(r"│$", "", line)

            cleaned_lines.append(line.rstrip() + "\n")

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(cleaned_lines)

        print(f"[OK] File cleaned: {path}")

    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 clean_file.py <file.py>")
        sys.exit(1)

    clean_file(sys.argv[1])
