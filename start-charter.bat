@echo off
setlocal
cd /d "%~dp0"
title Charter

echo.
echo Charter
echo This window starts the local lab. The first run can take several minutes.
echo.

where docker >nul 2>&1
if errorlevel 1 goto no_docker
docker info >nul 2>&1
if errorlevel 1 goto docker_stopped
docker compose version >nul 2>&1
if errorlevel 1 goto no_compose

if not exist "private\compose.env.example" (
    echo The file private\compose.env.example is missing. Download the repository again.
    goto fail
)

if exist "private\compose.env" goto have_env
echo Creating private\compose.env from the template.
copy /Y "private\compose.env.example" "private\compose.env" >nul
if errorlevel 1 (
    echo Could not create private\compose.env.
    goto fail
)
echo.
echo Open private\compose.env in Notepad and fill in the four CHARTER_LLM_ lines.
echo The file has a Claude example in the comments. Save the file, then double-click
echo start-charter.bat again if you want autonomous planning.
echo You can leave the four lines blank and still capture a URL from the dashboard.
echo.

:have_env
echo Building the lab image. Charter signing runs inside Docker, so Python is not required.
docker build -t charter-lab:local .
if errorlevel 1 (
    echo The lab image did not build.
    goto fail
)

echo Signing the one-hour local lab charter.
docker run --rm --user 0 -e HOME=/tmp -v "%CD%\private:/app/private" charter-lab:local python lab.py --operator local-operator --approve-local-lab
if errorlevel 1 (
    echo The lab charter was not signed.
    goto fail
)

echo Starting the lab.
docker compose --env-file private\compose.env up --build --wait -d
if errorlevel 1 (
    echo The lab did not start. If port 8000 or 5432 is already in use, close the other program and try again.
    goto fail
)

start "" "http://127.0.0.1:8000"
echo.
echo The dashboard is open at http://127.0.0.1:8000
echo Juice Shop, the bundled practice target, is at http://127.0.0.1:3000
findstr /X /C:"CHARTER_LLM_API_KEY=" "private\compose.env" >nul
if not errorlevel 1 (
    echo.
    echo Autonomous planning is off until private\compose.env has CHARTER_LLM_BASE_URL,
    echo CHARTER_LLM_API, CHARTER_LLM_API_KEY, and CHARTER_LLM_MODEL.
    echo Save that file and double-click start-charter.bat again.
)
echo.
echo Leave this lab running while you use the dashboard.
echo Double-click stop-charter.bat when you want to stop it.
echo.
pause
exit /b 0

:no_docker
echo Docker Desktop is not installed.
echo Install it from https://www.docker.com/products/docker-desktop/
echo Then start Docker Desktop and double-click start-charter.bat again.
goto fail

:docker_stopped
echo Docker Desktop is installed, but it is not running.
echo Open Docker Desktop and wait until it says Docker is running.
echo Then double-click start-charter.bat again.
echo Install page: https://www.docker.com/products/docker-desktop/
goto fail

:no_compose
echo Docker is running, but Docker Compose v2 is not available.
echo Update Docker Desktop from https://www.docker.com/products/docker-desktop/
goto fail

:fail
echo.
echo Charter did not start. Read the message above.
echo.
pause
exit /b 1
