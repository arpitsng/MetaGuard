@echo off
echo Starting MetaGuard Application...
echo.

echo Starting Backend Server (Python/FastAPI)...
start "MetaGuard Backend" cmd /k "cd /d D:\MetaGuard && python api.py"

echo Waiting 3 seconds for backend to start...
timeout /t 3 /nobreak > nul

echo Starting Frontend Server (React)...
start "MetaGuard Frontend" cmd /k "cd /d D:\MetaGuard\frontend && npm start"

echo.
echo MetaGuard is starting up!
echo Backend will be available at: http://localhost:8000
echo Frontend will be available at: http://localhost:3000
echo.
echo Press any key to close this window...
pause > nul 