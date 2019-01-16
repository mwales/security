@echo off

if %PROCESSOR_ARCHITECTURE% == AMD64 (
   echo Windows 64-bit detected
   set openSslBinary=openssl_windows_64bit\openssl
) else (
   echo Windows 32-bit detected
   set openSslBinary=openssl_windows_32bit\openssl
)

REM Get number or args passed in by user
SET /A ARGS_COUNT=0    
FOR %%A in (%*) DO SET /A ARGS_COUNT+=1    

if not %ARGS_COUNT% == 2 (
   echo "Usage: encrypt_file plaintext.txt ciphertext.bin"
   goto :eof
)

%openSslBinary% enc -md md5 -aes-256-cbc -salt -in %1 -out %2




@echo off
if %ERRORLEVEL% == 0 (
   echo Success
) else (
   echo Error during encryption
)

