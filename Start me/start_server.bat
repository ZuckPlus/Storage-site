@echo off
setlocal EnableDelayedExpansion

REM Create and start logging
echo %date% %time% - Starting start_server.bat > start_server_log.txt

REM Change to root directory
echo %date% %time% - Changing to root directory >> start_server_log.txt
cd /d C:\storage_system
echo %date% %time% - Current directory: %CD% >> start_server_log.txt

REM Check if server.py exists
if not exist "server.py" (
    echo %date% %time% - ERROR: server.py not found >> start_server_log.txt
    echo Error: server.py not found.
    echo Please run configure_server.bat first.
    pause
    exit /b 1
)
echo %date% %time% - server.py found >> start_server_log.txt

REM Activate virtual environment
echo %date% %time% - Activating virtual environment >> start_server_log.txt
call venv\Scripts\activate.bat
if !errorlevel! neq 0 (
    echo %date% %time% - ERROR: Failed to activate virtual environment >> start_server_log.txt
    echo Error: Failed to activate virtual environment
    pause
    exit /b 1
)
echo %date% %time% - Virtual environment activated successfully >> start_server_log.txt

REM Return to root directory
echo %date% %time% - Returning to root directory >> start_server_log.txt
cd /d C:\storage_system
echo %date% %time% - Current directory: %CD% >> start_server_log.txt

echo %date% %time% - Starting the server >> start_server_log.txt
echo Starting the server...
python server.py

echo %date% %time% - Server process ended >> start_server_log.txt
pause