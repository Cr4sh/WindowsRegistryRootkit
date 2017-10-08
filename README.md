
******************************************************************************

  Kernel rootkit, that lives inside the Windows registry value data.  
  By Oleksiuk Dmytro (aka Cr4sh)  
  
  http://twitter.com/d_olex  
  http://blog.cr4.sh  
  cr4sh0@gmail.com  

******************************************************************************
 
Rootkit uses the zero day vulnerability in win32k.sys (buffer overflow in function win32k!bInitializeEUDC()) to get the execution at the OS startup.
 
Features:
 
 * NDIS-based network backdoor (+ meterpreter/bind_tcp).
  
 * In order to avoid unknown executable code detection it moves itself in the memory over discardable sections of some default Windows drivers.
    
 * Completely undetectable by public anti-rootkit tools.
  
 * Working on Windows 7 (SP0, SP1) x86.


 ![diagram](https://raw.githubusercontent.com/Cr4sh/blog/master/windows-registry-rootkit/WindowsRegistryRootkit-execution.png)

 
This rootkit was originally presented at the ZeroNights 2012 conference during my talk.  
See the slides and videos for more information: https://raw.githubusercontent.com/Cr4sh/blog/master/windows-registry-rootkit/Applied-anti-forensics.pdf
