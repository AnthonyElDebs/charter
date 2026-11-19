@echo off
setlocal
cd /d "%~dp0"
title Stop Charter

where docker >nul 2>&1
if errorlevel 1 goto no_docker
docker info >nul 2>&1
if errorlevel 1 goto docker_stopped

if not exist "private\compose.env" (
    echo private\compose.env was not found, so there is no lab password to use.
    echo If the lab is still running, start Docker Desktop and run this file again after private\compose.env exists.
    goto done
)

echo Stopping Charter.
docker compose --env-file private\compose.env down
if errorlevel 1 (
    echo The lab did not stop. Read the message above.
    goto done
)
echo Charter has stopped. The saved database volume is still on this machine.
goto done

:no_docker
echo Docker Desktop is not installed, so there is no lab to stop.
echo https://www.docker.com/products/docker-desktop/
goto done

:docker_stopped
echo Docker Desktop is not running, so the lab is not running.
goto done

:done
echo.
pause
exit /b 0
