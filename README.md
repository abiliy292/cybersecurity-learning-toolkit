# Cybersecurity Learning Toolkit

A small, beginner-friendly Python project for learning basic defensive cybersecurity concepts.

## Features

- **Password strength checker** — gives simple feedback about password length and character variety.
- **File hash calculator** — calculates SHA-256 hashes for files to help verify file integrity.
- **Log analyzer** — counts common authentication-related keywords in a text log file for learning and defensive review.

These tools are educational. They are not a substitute for professional security tools or a full security audit.

## Requirements

- Python 3.10+
- No third-party dependencies

## Run

```bash
python toolkit.py
```

Or run a specific tool:

```bash
python toolkit.py password
python toolkit.py hash path/to/file
python toolkit.py logs path/to/logfile.txt
```

## Safety and privacy

- The password checker does not send or store passwords.
- Do not use real passwords when demonstrating or recording results.
- Only analyze log files you are authorized to access.
- The log analyzer uses simple keyword matching and may produce false positives or miss events.

## Contributing

Issues, documentation improvements, tests, and small defensive features are welcome. Please avoid adding features that enable unauthorized access or harm.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
