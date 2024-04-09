# LFInc.py - Local File Inclusion Scanner

LFInc.py is a Python script designed to scan a target URL for Local File Inclusion (LFI) vulnerabilities by sending payloads to the request parameter in the URL. When a vulnerable URL is detected, it provides an option to establish a reverse shell. However, the reverse shell must be initiated separately in another terminal, specifying the host and port using the parameters -p and -h when starting LFInc.py.

## Features

- Scans a target URL for Local File Inclusion vulnerabilities.
- Sends payloads to the request parameter in the URL.
- Provides an option to establish a reverse shell upon detecting a vulnerable URL.
- Easy-to-use command-line interface with parameter options.

## Requirements

- Python 3.x
- Requests library (`pip install requests`)

## Usage

- `-u <URL>`: Specifies the target URL to scan.
- `--lhost`: Specifies the address to talk back to
- `--lport`: The port of the listener
- `--rfi`: Also check for RFI
- `-r`: The file to upload when checking for RFI
- `-f`: A file which you know is in the same directory on the server you make the request
- `-p`: A payload for wrapper (Default: "<?php echo shell_exec('id'); ?>")
- `-s`: Specify a reverse shell type (valid shells: python, python3, ruby, perl, bash) default: python3


After detecting a vulnerable URL and selecting the reverse shell option, initiate the reverse shell in another terminal with the desired host and port using the following command:

nc -l -p <PORT> -vv


## Disclaimer

This tool is designed for educational purposes and should only be used against systems for which you have explicit permission to test. Misuse of this tool could result in legal consequences. The author assumes no liability for any misuse or damage caused by this script.

