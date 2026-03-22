@echo off
setlocal
set ROOT=%~dp0

rem Default: open in a new window unless --current-window is provided.
set IS_CHILD=0
set CURRENT=0
for %%A in (%*) do (
	if "%%~A"=="--child" set IS_CHILD=1
	if "%%~A"=="--current-window" set CURRENT=1
)
if %IS_CHILD%==0 if %CURRENT%==0 (
	set ARGS=%*
	set ARGS=%ARGS:--current-window=%
	set ARGS=%ARGS:--child=%
	start "Django Dev Up" cmd /k "%~f0" --child %ARGS%
	goto :eof
)

rem Try common venv folders
set VENV=
for %%V in (server_venv venv .venv) do (
	if exist "%ROOT%%%V\Scripts\activate.bat" (
		set VENV=%ROOT%%%V
		call "%ROOT%%%V\Scripts\activate.bat"
		goto :venv_found
	)
)
:venv_found

set PY=python
if defined VENV if exist "%VENV%\Scripts\python.exe" set PY=%VENV%\Scripts\python.exe

rem Strip control flags for inner execution
set CLEAN=%*
set CLEAN=%CLEAN:--current-window=%
set CLEAN=%CLEAN:--child=%
"%PY%" "%ROOT%manage.py" dev_up --no-input %CLEAN%
