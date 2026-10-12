"""Beginner-friendly defensive cybersecurity learning tools."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


def check_password_strength(password: str) -> tuple[str, list[str]]:
    """Return a simple strength label and suggestions; never stores the password."""
    suggestions: list[str] = []
    score = 0

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Consider adding symbols.")

    if score >= 6:
        label = "Strong (basic estimate)"
    elif score >= 4:
        label = "Moderate (basic estimate)"
    else:
        label = "Weak (basic estimate)"

    return label, suggestions


def sha256_file(file_path: str) -> str:
    """Calculate a file's SHA-256 digest without loading the whole file into memory."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_log(file_path: str) -> dict[str, int]:
    """Count selected keywords in an authorized text log (simple learning demo)."""
    patterns = {
        "failed": re.compile(r"failed|failure|invalid password", re.IGNORECASE),
        "successful": re.compile(r"accepted|successful login|authentication success", re.IGNORECASE),
        "locked": re.compile(r"locked|account disabled|too many attempts", re.IGNORECASE),
    }
    counts = {name: 0 for name in patterns}

    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            for name, pattern in patterns.items():
                if pattern.search(line):
                    counts[name] += 1
    return counts


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in {"-h", "--help", "help"}:
        print(__doc__)
        print("Usage:")
        print("  python toolkit.py password")
        print("  python toolkit.py hash <file>")
        print("  python toolkit.py logs <logfile>")
        return 0

    command = argv[1].lower()

    if command == "password":
        # Input is hidden from neither terminal history nor screen; use a demo password only.
        import getpass
        password = getpass.getpass("Enter a test password (not a password you use elsewhere): ")
        label, suggestions = check_password_strength(password)
        print(f"Result: {label}")
        if suggestions:
            print("Suggestions:")
            for suggestion in suggestions:
                print(f"- {suggestion}")
        else:
            print("No basic suggestions. Consider using a password manager and a unique passphrase.")
        return 0

    if command == "hash":
        if len(argv) != 3:
            print("Usage: python toolkit.py hash <file>", file=sys.stderr)
            return 2
        path = Path(argv[2])
        if not path.is_file():
            print(f"File not found: {path}", file=sys.stderr)
            return 1
        print(f"SHA-256  {sha256_file(str(path))}  {path}")
        return 0

    if command == "logs":
        if len(argv) != 3:
            print("Usage: python toolkit.py logs <logfile>", file=sys.stderr)
            return 2
        path = Path(argv[2])
        if not path.is_file():
            print(f"File not found: {path}", file=sys.stderr)
            return 1
        counts = analyze_log(str(path))
        print("Keyword counts (educational heuristic, not a security verdict):")
        for name, count in counts.items():
            print(f"- {name}: {count}")
        return 0

    print(f"Unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
