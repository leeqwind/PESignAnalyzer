rem 这个脚本用来在更新代码之后清除一些不要提交到GIT上的东西
@echo off
echo 清理脚本开始执行
echo 当前路径
cd

echo 清理Honeypot冗余文件

for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\Debug" rd /S /Q "%%c\Debug"
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\Release" rd /S /Q "%%c\Release"
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\x64" rd /S /Q "%%c\x64"

echo GIT上存档的版本,不要保留bin
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\Bin" rd /S /Q "%%c\Bin"

echo GIT上存档的版本,不要保留PDB
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\Symbols" rd /S /Q "%%c\Symbols"

for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\objchk_win7_x86" rd /S /Q "%%c\objchk_win7_x86"
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\objchk_win7_amd64" rd /S /Q "%%c\objchk_win7_amd64"
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\objfre_win7_x86" rd /S /Q "%%c\objfre_win7_x86"
for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\objfre_win7_amd64" rd /S /Q "%%c\objfre_win7_amd64"

for /r ..\Honeypot\honeypot\ %%c in (.) do @if exist "%%c\objchk_wxp_x86" rd /S /Q "%%c\objchk_wxp_x86"

for /r ..\Honeypot\honeypot\ %%c in (*.aps *.bsc *.clw *.ilk *.log *.mac *.ncb *.obj *.opt *.plg *.positions *.suo *.user *.WW *.i) do del /f /q /s /A "%%c"

echo 清理Lightvm冗余文件

for /r ..\Lightvm\lightvm\ %%c in (.) do @if exist "%%c\Debug" rd /S /Q "%%c\Debug"
for /r ..\Lightvm\lightvm\ %%c in (.) do @if exist "%%c\Release" rd /S /Q "%%c\Release"

for /r . %%c in (.) do @if exist "%%c\Debug" rd /S /Q "%%c\Debug"
for /r . %%c in (.) do @if exist "%%c\Release" rd /S /Q "%%c\Release"

for /r ..\Lightvm\lightvm\ %%c in (*.aps *.bsc *.clw *.ilk *.log *.mac *.ncb *.obj *.opt *.plg *.positions *.suo *.user *.WW *.i) do del /f /q /s /A "%%c"

echo 清理解决方案冗余文件

for /r . %%c in (*.aps *.bsc *.clw *.ilk *.log *.mac *.ncb *.obj *.opt *.plg *.sdf *.positions *.suo *.user *.WW *.i) do del /f /q /s /A "%%c"