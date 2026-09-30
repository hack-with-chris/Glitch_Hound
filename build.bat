@echo off
echo Installing PyInstaller if needed...
pip install pyinstaller --quiet

echo.
echo Building GlitchHound.exe...
pyinstaller glitchhound.spec --clean

echo.
echo Done. Find your exe in the dist\GlitchHound folder (or dist\GlitchHound.exe).
echo Remember to copy your .env file into the same folder as the .exe before running it.
pause
