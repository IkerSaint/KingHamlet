# KingHamlet
Process Ghosting Tool - 64 bits Only!

King Hamlet is a simple tool, which allows you to perform a Process Ghosting Attack (https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack).

Initially you have to encrypt a file, which is later located on the system to be attacked, after, the tool is used to decrypt the file and create a process using the
Process Ghosting technique; this allows to bypass a significant number of security solutions.

The options are very simple:

```bash
Usage:
        Encrypt a file:
                kh.exe <sourcefile.exe> <encryptkey>

        Execute a file:
                kh.exe <encryptedfile.khe> <encryptkey> <targetfile.exe>

The End.
```
## Encrypt a File
* sourcefile.exe - File that is going to be encrypted - 64 bit executables only
* encryptkey - Key use to encrypt the file, 16 bytes top, otherwise it's gonna be trim

## Execute a file:
* sourcefile.exe - File encrypted, that is going to be executed
* encryptkey - Key use to decrypt the file
* targetfile.exe - File "created" temporarily for the process

Antivirus Solutions bypassed without any issues:

Antivirus | Date
------------ | -------------
Kaspkersy | 18/06/2021
ESET NOD32 | 18/06/2021
TrendMicro Maximum Security | 18/06/2021
McAfee Total Protection | 18/06/2021
Windows Defender | 18/06/2021
Avast Free Antivirus | 18/06/2021
Avast Free Security | 18/06/2021

## Credits:  
https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack  
https://github.com/hasherezade/process_doppelganging  
https://github.com/bricke/tiny-AES-C  
https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf  


All material in this repository is in the public domain.
