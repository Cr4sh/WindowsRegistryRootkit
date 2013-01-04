@echo off
if exist ..\meterpreter_debug.dll ..\bin2c.exe ..\meterpreter_debug.dll dll > ..\includes\meterpreter_debug.dll.h
if exist ..\meterpreter.dll ..\bin2c.exe ..\meterpreter.dll dll > ..\includes\meterpreter.dll.h
pause