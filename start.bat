@echo off
title Aegis
cd /d "%~dp0"

rem Find Python: prefer the "py" launcher (works even when python is not on
rem PATH, e.g. right after a winget install), then fall back to "python".
set "PY="
where py >nul 2>nul && set "PY=py -3.12"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" set "PY="%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" -3.12"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python is not installed. Install it with:  winget install Python.Python.3.12
  echo Then close this window and double-click start.bat again.
  pause
  exit /b 1
)

if not exist .venv (
  echo First run: setting up, this takes about a minute...
  %PY% -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt

echo.
echo  Aegis is running at  http://127.0.0.1:8000
echo  Close this window to stop it.
echo.
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8000"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
