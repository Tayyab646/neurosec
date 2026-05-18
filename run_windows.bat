@echo off
title AgentFirewall v2
cd /d D:\AgentFirewall\AgentFirewall
set PYTHONPATH=%CD%
echo.
echo =============================================
echo   AgentFirewall v2 - Starting...
echo =============================================
echo.
echo Checking Python...
python --version
echo.
echo Starting server...
python server.py
echo.
pause