// Package capture lists interfaces, captures live traffic through libpcap
// in a separate helper process, and follows growing capture files.
package capture

/*

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ls_compile(int linktype, int snaplen, const char *expr, char *errbuf, int *ninsns) {
	pcap_t *p = pcap_open_dead(linktype, snaplen);
	if (p == NULL) {
		snprintf(errbuf, 256, "pcap_open_dead failed");
		return -1;
	}
	struct bpf_program prog;
	if (pcap_compile(p, &prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		snprintf(errbuf, 256, "%s", pcap_geterr(p));
		pcap_close(p);
		return -1;
	}
	*ninsns = (int)prog.bf_len;
	pcap_freecode(&prog);
	pcap_close(p);
	return 0;
}
*/
import "C"

import (
	"errors"
	"strings"
	"unsafe"
)

// CheckFilter validates a capture (BPF) filter for a link type without
// needing capture privileges. It returns the number of BPF instructions.
func CheckFilter(linkType int, expr string) (int, error) {
	if strings.TrimSpace(expr) == "" {
		return 0, nil
	}
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))
	var errbuf [256]C.char
	var n C.int
	if C.ls_compile(C.int(linkType), 262144, cexpr, &errbuf[0], &n) < 0 {
		return 0, errors.New(C.GoString(&errbuf[0]))
	}
	return int(n), nil
}
