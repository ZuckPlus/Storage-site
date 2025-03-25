@echo off
setlocal EnableDelayedExpansion

REM Create and start logging
echo %date% %time% - Starting configure_server.bat > configure_log.txt

REM Change to root directory
echo %date% %time% - Changing to root directory >> configure_log.txt
cd /d C:\storage_system
echo %date% %time% - Current directory: %CD% >> configure_log.txt

REM Activate virtual environment
echo %date% %time% - Activating virtual environment >> configure_log.txt
call venv\Scripts\activate.bat
if !errorlevel! neq 0 (
    echo %date% %time% - ERROR: Failed to activate virtual environment >> configure_log.txt
    echo Error: Failed to activate virtual environment
    pause
    exit /b 1
)
echo %date% %time% - Virtual environment activated successfully >> configure_log.txt

REM Return to root directory
echo %date% %time% - Returning to root directory >> configure_log.txt
cd /d C:\storage_system
echo %date% %time% - Current directory: %CD% >> configure_log.txt

REM Check if server.py exists
if exist "server.py" (
    echo %date% %time% - server.py found, no need to create >> configure_log.txt
    echo server.py is already set up. Please run start_server.bat
    pause
    exit /b 0
)

echo %date% %time% - server.py not found, creating new one >> configure_log.txt

REM Get IPv4 Address
echo %date% %time% - Detecting IP address >> configure_log.txt
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /r /c:"IPv4 Address"') do (
    set "IP=%%a"
    set "IP=!IP:~1!"
    goto :found_ip
)
:found_ip
echo %date% %time% - IP Address found: !IP! >> configure_log.txt

REM Create new server.py file
echo %date% %time% - Creating new server.py file >> configure_log.txt
echo from app import create_app > "server.py"
echo import logging >> "server.py"
echo import os >> "server.py"
echo. >> "server.py"
echo # Configure logging >> "server.py"
echo logging.basicConfig( >> "server.py"
echo     level=logging.INFO, >> "server.py"
echo     format='%%(asctime)s - %%(name)s - %%(levelname)s - %%(message)s', >> "server.py"
echo     handlers=[ >> "server.py"
echo         logging.StreamHandler() >> "server.py"
echo     ] >> "server.py"
echo ) >> "server.py"
echo. >> "server.py"
echo logger = logging.getLogger(__name__) >> "server.py"
echo logger.info("Starting the Storage System application") >> "server.py"
echo. >> "server.py"
echo app = create_app() >> "server.py"
echo. >> "server.py"
echo if __name__ == "__main__": >> "server.py"
echo     logger.info("Running server with threading enabled") >> "server.py"
echo     app.run(host="!IP!", port=3240, debug=False, threaded=True) >> "server.py"

REM Verify the file was created
if not exist "server.py" (
    echo %date% %time% - ERROR: Failed to create server.py >> configure_log.txt
    echo Error: Failed to create server.py
    pause
    exit /b 1
)

echo %date% %time% - server.py created successfully >> configure_log.txt
echo.
echo Setup complete! Server will run with:
echo IP Address: !IP!
echo Port: 3240
echo Debug Mode: False
echo Threaded Mode: True
echo.
echo You can now run 'start_server.bat' to start the application.
echo.

echo %date% %time% - Configuration completed successfully >> configure_log.txt
pause