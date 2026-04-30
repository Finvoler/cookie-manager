# Cookie Manager

A small offline desktop vault for cookies, website accounts, passwords, tokens, and notes.

Cookie Manager keeps data on your own machine. Records are stored in an encrypted `vault.dat` file protected by a master password, and the app does not require a network connection to use.

## Features

- Local encrypted vault created on first launch.
- Modern rounded desktop UI built with CustomTkinter.
- Two clean views: one for saving entries, one for searching and viewing them.
- Entry fields for name, account, password, notes, and full cookie / extra information.
- Keyword search across entry names and notes.
- Show / hide password controls.
- Strong password generator.
- Copy account, password, or cookie content to the clipboard.
- Delete saved entries.
- Windows executable build script included.

## Screens

- Save Data: save a name, account, password, note, and website cookie / token / secret text.
- Search & View: filter by keyword, inspect full details, select text, copy fields, or delete records.

## Requirements

- Python 3.10+
- Windows, macOS, or Linux with Tkinter support
- `cryptography`
- `customtkinter`

## Windows EXE

Download or build `CookieManager.exe`, then double-click it.

The first launch creates a local `vault.dat` next to the executable. That file contains encrypted personal data and should not be committed or shared.

## Run From Source

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start the app:

```powershell
python app.py
```

## Build A Windows EXE

On Windows, double-click `build_exe.bat`, or run:

```powershell
.\build_exe.bat
```

The executable will be generated and copied to:

```text
CookieManager.exe
```

The build script creates a local `.venv` so PyInstaller dependencies do not need to be installed globally.

## Data And Security Notes

- Your vault is saved as `vault.dat` next to the source script, or next to the `.exe` when running the packaged app.
- The vault is encrypted with a key derived from your master password using PBKDF2-HMAC-SHA256 and Fernet encryption.
- The master password is never stored.
- If you forget the master password, existing vault data cannot be recovered.
- Do not commit or publish `vault.dat`; it is ignored by default.

This is a lightweight personal tool. For high-risk production credentials, consider a professionally audited password manager.

## Project Structure

```text
cookie-manager/
├── app.py                 # Tkinter desktop app and encrypted vault logic
├── requirements.txt       # Runtime and packaging dependencies
├── build_exe.bat          # Windows PyInstaller build helper
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE) for details.
