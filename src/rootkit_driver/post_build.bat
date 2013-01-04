@echo off
if exist ..\rootkit_driver_debug.sys ..\bin2c.exe ..\rootkit_driver_debug.sys rootkit_driver > ..\includes\rootkit_driver_debug.sys.h
if exist ..\rootkit_driver.sys ..\bin2c.exe ..\rootkit_driver.sys rootkit_driver > ..\includes\rootkit_driver.sys.h
pause