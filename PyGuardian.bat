@echo off
:menu
echo ==============================================
echo          AES Encryption/Decryption Tool Menu
echo ==============================================
echo 1. AES-CBC with Manual Key and IV (PyGuardian-V1.py)
echo 2. AES-CBC with Password-Derived Key and Auto IV (PyGuardian-V2.py)
echo 3. AES-CBC with Salted Password-Derived Key and Auto IV (PyGuardian-V2.1.py)
echo 4. AES-GCM with Salted Password-Derived Key and Integrity Check (PyGuardian-V3.py)
echo 5. Exit
echo ==============================================
set /p choice="Choose an option (1-5): "

if "%choice%"=="1" goto runV1
if "%choice%"=="2" goto runV2
if "%choice%"=="3" goto runV21
if "%choice%"=="4" goto runV3
if "%choice%"=="5" goto exit
echo Invalid choice, please select a valid option.
goto menu

:runV1
echo Running AES-CBC with Manual Key and IV (PyGuardian-V1.py)...
python PyGuardian-V1.py
goto menu

:runV2
echo Running AES-CBC with Password-Derived Key and Auto IV (PyGuardian-V2.py)...
python PyGuardian-V2.py
goto menu

:runV21
echo Running AES-CBC with Salted Password-Derived Key and Auto IV (PyGuardian-V2.1.py)...
python PyGuardian-V2.1.py
goto menu

:runV3
echo Running AES-GCM with Salted Password-Derived Key and Integrity Check (PyGuardian-V3.py)...
python PyGuardian-V3.py
goto menu

:exit
echo Exiting...
exit
