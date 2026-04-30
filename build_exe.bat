@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --collect-all customtkinter --name CookieManager app.py
if exist "dist\CookieManager.exe" (
  copy /Y "dist\CookieManager.exe" "CookieManager.exe"
  echo.
  echo Build complete: CookieManager.exe
) else (
  echo.
  echo Build failed. Please check the messages above.
)
pause
