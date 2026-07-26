@echo off
echo Starting RentReviews Local Development Server...
echo.
echo Your website will be available at:
echo http://localhost:5500
echo.
echo (Port 5500 is used because it's the one already whitelisted in the
echo  backend services' CORS config — see property-service/server.js)
echo.
echo Press Ctrl+C to stop the server
echo.
python -m http.server 5500
