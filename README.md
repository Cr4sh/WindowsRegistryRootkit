
******************************************************************************

  Kernel rootkit, that lives inside the Windows registry value data
  By Oleksiuk Dmytro (aka Cr4sh)
  
  http://twitter.com/d_olex
  http://blog.cr4.sh
  mailto:cr4sh0@gmail.com

******************************************************************************
 
Rootkit uses the zero day vulnerability in win32k.sys (buffer overflow in function win32k!bInitializeEUDC()) to get the execution at the OS startup.
 
Features:
 
 * NDIS-based network backdoor (+ meterpreter/bind_tcp).
  
 * In order to avoid unknown executable code detection it moves itself in the memory over discardable sections of some default Windows drivers.
    
 * Completely undetectable by public anti-rootkit tools.
  
 * Working on Windows 7 (SP0, SP1) x86.


 ![foo](http://dl.dropbox.com/u/22903093/WindowsRegistryRootkit-execution.png)

 
This rootkit was originally presented at the ZeroNights 2012 conference during my talk.
See the slides and videos for more information: http://dl.dropbox.com/u/22903093/Applied-anti-forensics.pdf
 
 
