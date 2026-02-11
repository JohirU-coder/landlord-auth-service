@echo off
echo ===================================
echo RentReviews Translation Script
echo ===================================
echo.
echo This script will automatically translate all your
echo English content to Spanish and Chinese using DeepL.
echo.
echo IMPORTANT: You need a DeepL API key first!
echo Get one free at: https://www.deepl.com/pro-api
echo.
echo ===================================
echo.

REM Check if API key is set
if "%DEEPL_API_KEY%"=="" (
    echo ERROR: DEEPL_API_KEY environment variable not set!
    echo.
    echo Please set your API key first:
    echo set DEEPL_API_KEY=your-key-here
    echo.
    echo Then run this script again.
    echo.
    pause
    exit /b 1
)

echo Starting translation...
echo.
node translate-with-deepl.js

echo.
echo ===================================
echo Translation Complete!
echo ===================================
echo.
echo Next steps:
echo 1. Test your site: start-server.bat
echo 2. Visit: http://localhost:8000
echo 3. Try switching languages!
echo.
pause
