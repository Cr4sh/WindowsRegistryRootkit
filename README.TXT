
******************************************************************************

  Kernel rootkit, that lives inside the Windows registry value data.

    By Oleksiuk Dmytro (aka Cr4sh)
    http://twitter.com/d_olex
    http://blog.cr4.sh
    mailto:cr4sh0@gmail.com

******************************************************************************
 
 It uses the zero day vulnerability in win32k.sys (buffer overflow
 in function win32k!bInitializeEUDC()) to get the execution at the
 OS startup.
 
 This rootkit was originally presented at the ZeroNights 2012 conference
 during my talk.
 
 See the slides and videos for more information:
 http://dl.dropbox.com/u/22903093/Applied-anti-forensics.pdf
 
 Working on Windows 7 (SP0, SP1) x86.
 
