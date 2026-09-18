@echo off
setlocal
pushd "%~dp0"

for %%d in (.build "MSVC\Debug" "MSVC\Release" "MSVC\x64") do (
    if exist "%%~d" rd /S /Q "%%~d"
)

popd
endlocal
