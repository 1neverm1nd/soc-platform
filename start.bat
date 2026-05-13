@echo off
echo Starting SOC Platform...
echo.

echo [1/2] Starting Backend (http://localhost:3001)...
start "SOC Backend" cmd /k "cd /d %~dp0backend && npx tsx src/index.ts"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Frontend (http://localhost:3000)...
start "SOC Frontend" cmd /k "cd /d %~dp0frontend && npx vite --port 3000"

timeout /t 4 /nobreak >nul

echo.
echo =========================================
echo   SOC Platform is running!
echo   Open: http://localhost:3000
echo   Login: admin / admin123
echo =========================================
echo.
start http://localhost:3000
