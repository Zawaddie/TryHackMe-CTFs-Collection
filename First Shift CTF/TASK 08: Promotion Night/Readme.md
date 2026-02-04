# TASK 08: Promotion Night

## Questions to Answer:

Q1. What was the network share path where ransomware was placed? \\DC-01\SYSVOL\gaze.exe

Since the ransomware was a network share and was placed, we concentrate in looking for a UNC path (\\), an executable file, a file creation/copy event (eventID 11) and then the full file path field which may look like \\HostName\Share\folder\file.exe.


Search Query: 

```
index=scenario *copy* *\\* *.exe*
```


<img width="800" height="367" alt="image" src="https://github.com/user-attachments/assets/a2cd115f-c979-47ec-87c8-bd83549fe801" />


Q2. What is the value ransomware created to persist on reboot? BabyLockerKZ

While working on the first Question we note the target is the jump server: host=SRV-JMP so we can narrow our serach queries with this as host.
Since we know it is a ransomware, we first look fordetection of ransomware_like behaviour by looking for encryption or backup-deletion commands and showing key forensic details in time order. Query:

```
index=scenario host=SRV-JMP *shadow* *vssadmin* *Delete* 
| table _EventCode ProcessName CommandLine ObjectName User
| sort _time
```

<img width="800" height="331" alt="image" src="https://github.com/user-attachments/assets/6301eb6d-ad08-4e34-93a8-a98c87ccbed4" />

looking for common malware behavior.For persistence on reboot, we look for registry Run Keys.

```bash
index=scenario RunOnce OR Run OR registry
```

Run Keys are special registry locations that tell Windows:"When the computer starts or the user logs in, automatically run this program." So anything placed here will execute on every reboot


```bash
index=scenario *CurrentVersion\\RunOnce* OR *CurrentVersion\\Run* 
| table _time host User EventCode TargetObject Details Image
| sort _time
```


<img width="800" height="275" alt="image" src="https://github.com/user-attachments/assets/816a1a8a-e95a-4e11-a319-24f623dbe558" />


Q3. What was the most likely extension of the encrypted files?
Here, we lookup the hashes of the created ransomware file, \\DC-01\SYSVOL\gaze.exe from VirusTotal and see what information we can get.


<img width="800" height="399" alt="image" src="https://github.com/user-attachments/assets/ffaec34e-2a82-496e-a861-fc7e09440a44" />


```plain text
Hashes:
MD5=390B2038C9ED2C94AB505921BC827FC7, 
SHA256=34C4ED50A3441BD7CB6411749771C637A8C18C791525D8FCB5AE71B0B1969BA6, 
IMPHASH=AF8CD6625FCE3244397EE550EFF4091
```


Q4. Which MITRE technique ID was used to deploy ransomware?

Q5. What ports of SRV-ITFS did the adversary successfully scan?

Q6. What is the full path to the malware that performed the Discovery?

Q7. Which artifact did the adversary create to persist on the beachhead?

Q8. What is the MD5 hash of the embedded initial shellcode?

Q9. Which C2 framework was used by the adversary in the intrusion?

Q10. What hostname did the adversary log in from on the beachhead?

Q11. What was the UNC path that likely contained AWS credentials?

Q13. From which IP address did the adversary access AWS?

Q13. Which two sensitive files did the adversary exfiltrate from AWS?


<img width="613" height="412" alt="image" src="https://github.com/user-attachments/assets/d76f3d58-dc10-4973-9add-38dffe0c3a57" />


Q14. What file did the adversary upload to S3 in place of the wiped ones?
