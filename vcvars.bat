@echo off

rem ****************************************************************
rem EDIT THESE VARIABLES
rem ****************************************************************
set VC_DIR=C:\Program Files\Microsoft Visual C++ Toolkit 2003
set SDK_DIR=C:\Program Files\Microsoft Platform SDK for Windows XP SP2
set DOTNET_DIR=C:\Program Files\Microsoft Visual Studio .NET 2003
set TWAIN_DIR=C:\Program Files\TWAIN Working Group\TWAIN Toolkit\twcommon
set PYTHON_DIR=C:\Program Files\Python26


rem ****************************************************************
rem Do not edit these variables.
rem ****************************************************************

Set PATH=%VC_DIR%\bin;%SDK_DIR%\Bin;%PYTHON_DIR%;%PATH%

Set INCLUDE=%VC_DIR%\include;%SDK_DIR%\Include;%PYTHON_DIR%\include;%TWAIN_DIR%;%INCLUDE%

Set LIB=%DOTNET_DIR%\Vc7\lib;%VC_DIR%\lib;%SDK_DIR%\Lib;%PYTHON_DIR%\libs;%LIB%

echo Visit http://msdn.microsoft.com/visualc/using/documentation/default.aspx for
echo complete compiler documentation.