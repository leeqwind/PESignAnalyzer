@echo off
cd
for /r . %%c in (.) do @if exist "%%c\Debug" rd /S /Q "%%c\Debug"
for /r . %%c in (.) do @if exist "%%c\Release" rd /S /Q "%%c\Release"
for /r . %%c in (*.aps *.bsc *.clw *.ilk *.log *.mac *.ncb *.obj *.opt *.sdf *.plg *.positions *.suo *.user *.WW *.i) do del /f /q /s /A "%%c"