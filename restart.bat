@echo off
echo ============================================
echo  Killing ALL Python processes...
echo ============================================
taskkill /F /IM python.exe 2>nul
taskkill /F /IM python3.exe 2>nul
timeout /t 2 /nobreak >nul
echo All Python processes killed.
echo.
echo ============================================
echo  Starting Flask server with --reset...
echo ============================================
echo.
python app.py --reset --debug
pause
