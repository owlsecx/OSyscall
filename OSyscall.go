// ============================================================
//
//	OSyscall — Linux x86_64 Syscall Reference · /proc Activity
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only, CGO disabled, static build) — OWL suite
//
//	A curated x86_64 syscall table (numbers, names, signatures and
//	security notes) plus a live view of what the running system is
//	doing: read /proc/<pid>/syscall for one task, or sample every
//	task and summarise which syscalls processes are blocked in.
//
// ============================================================
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const BANNER = `
 ██████╗ ███████╗██╗   ██╗███████╗ ██████╗ █████╗ ██╗     ██╗
██╔═══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗██║     ██║
██║   ██║███████╗ ╚████╔╝ ███████╗██║     ███████║██║     ██║
██║   ██║╚════██║  ╚██╔╝  ╚════██║██║     ██╔══██║██║     ██║
╚██████╔╝███████║   ██║   ███████║╚██████╗██║  ██║███████╗███████╗
 ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝
`

const (
	APPNAME = "OSyscall"
	SUITE   = "Owl System Suite"
	SUBLINE = "x86_64 syscall reference · security notes · live /proc view"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Syscall table (Linux x86_64, subset of asm/unistd_64.h).
// Note holds a short security/behaviour note for notable syscalls (empty = none).
// ---------------------------------------------------------------------------

type scEnt struct {
	Num  int
	Name string
	Args string
	Note string // security note; non-empty => flagged "notable"
}

func (s scEnt) notable() bool { return s.Note != "" }

var syscalls = []scEnt{
	{0, "read", "unsigned int fd, char *buf, size_t count", ""},
	{1, "write", "unsigned int fd, const char *buf, size_t count", ""},
	{2, "open", "const char *filename, int flags, umode_t mode", ""},
	{3, "close", "unsigned int fd", ""},
	{4, "stat", "const char *filename, struct stat *statbuf", ""},
	{5, "fstat", "unsigned int fd, struct stat *statbuf", ""},
	{6, "lstat", "const char *filename, struct stat *statbuf", ""},
	{7, "poll", "struct pollfd *ufds, unsigned int nfds, int timeout", ""},
	{8, "lseek", "unsigned int fd, off_t offset, unsigned int whence", ""},
	{9, "mmap", "void *addr, size_t len, int prot, int flags, int fd, off_t off", "RWX mappings enable code injection; watch PROT_EXEC"},
	{10, "mprotect", "unsigned long start, size_t len, unsigned long prot", "flipping a page to PROT_EXEC is a classic shellcode step"},
	{11, "munmap", "unsigned long addr, size_t len", ""},
	{12, "brk", "unsigned long brk", ""},
	{13, "rt_sigaction", "int sig, const struct sigaction *act, ...", ""},
	{14, "rt_sigprocmask", "int how, sigset_t *set, sigset_t *oldset, size_t sigsetsize", ""},
	{16, "ioctl", "unsigned int fd, unsigned int cmd, unsigned long arg", ""},
	{17, "pread64", "unsigned int fd, char *buf, size_t count, loff_t pos", ""},
	{18, "pwrite64", "unsigned int fd, const char *buf, size_t count, loff_t pos", ""},
	{19, "readv", "unsigned long fd, const struct iovec *vec, unsigned long vlen", ""},
	{20, "writev", "unsigned long fd, const struct iovec *vec, unsigned long vlen", ""},
	{21, "access", "const char *filename, int mode", ""},
	{22, "pipe", "int *fildes", ""},
	{23, "select", "int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timeval *tvp", ""},
	{24, "sched_yield", "", ""},
	{25, "mremap", "unsigned long addr, unsigned long old_len, unsigned long new_len, ...", ""},
	{28, "madvise", "unsigned long start, size_t len, int behavior", ""},
	{32, "dup", "unsigned int fildes", ""},
	{33, "dup2", "unsigned int oldfd, unsigned int newfd", ""},
	{35, "nanosleep", "struct timespec *req, struct timespec *rem", ""},
	{39, "getpid", "", ""},
	{41, "socket", "int family, int type, int protocol", "network egress / C2 channels start here"},
	{42, "connect", "int fd, struct sockaddr *uservaddr, int addrlen", "outbound connections; reverse-shell indicator"},
	{43, "accept", "int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen", ""},
	{44, "sendto", "int fd, void *buff, size_t len, unsigned int flags, ...", ""},
	{45, "recvfrom", "int fd, void *ubuf, size_t size, unsigned int flags, ...", ""},
	{46, "sendmsg", "int fd, struct user_msghdr *msg, unsigned int flags", ""},
	{47, "recvmsg", "int fd, struct user_msghdr *msg, unsigned int flags", ""},
	{48, "shutdown", "int fd, int how", ""},
	{49, "bind", "int fd, struct sockaddr *umyaddr, int addrlen", "bind shells / listeners"},
	{50, "listen", "int fd, int backlog", ""},
	{51, "getsockname", "int fd, struct sockaddr *usockaddr, int *usockaddr_len", ""},
	{52, "getpeername", "int fd, struct sockaddr *usockaddr, int *usockaddr_len", ""},
	{53, "socketpair", "int family, int type, int protocol, int *usockvec", ""},
	{54, "setsockopt", "int fd, int level, int optname, char *optval, int optlen", ""},
	{55, "getsockopt", "int fd, int level, int optname, char *optval, int *optlen", ""},
	{56, "clone", "unsigned long clone_flags, unsigned long newsp, ...", "namespace flags (CLONE_NEWUSER etc.) → container/sandbox escapes"},
	{57, "fork", "", ""},
	{58, "vfork", "", ""},
	{59, "execve", "const char *filename, const char *const argv[], const char *const envp[]", "process execution — primary malware/exploit indicator"},
	{60, "exit", "int error_code", ""},
	{61, "wait4", "pid_t upid, int *stat_addr, int options, struct rusage *ru", ""},
	{62, "kill", "pid_t pid, int sig", ""},
	{63, "uname", "struct old_utsname *name", ""},
	{72, "fcntl", "unsigned int fd, unsigned int cmd, unsigned long arg", ""},
	{74, "fsync", "unsigned int fd", ""},
	{76, "truncate", "const char *path, long length", ""},
	{77, "ftruncate", "unsigned int fd, unsigned long length", ""},
	{78, "getdents", "unsigned int fd, struct linux_dirent *dirent, unsigned int count", ""},
	{79, "getcwd", "char *buf, unsigned long size", ""},
	{80, "chdir", "const char *filename", ""},
	{81, "fchdir", "unsigned int fd", ""},
	{82, "rename", "const char *oldname, const char *newname", ""},
	{83, "mkdir", "const char *pathname, umode_t mode", ""},
	{84, "rmdir", "const char *pathname", ""},
	{85, "creat", "const char *pathname, umode_t mode", ""},
	{86, "link", "const char *oldname, const char *newname", ""},
	{87, "unlink", "const char *pathname", ""},
	{88, "symlink", "const char *oldname, const char *newname", ""},
	{89, "readlink", "const char *path, char *buf, int bufsiz", ""},
	{90, "chmod", "const char *filename, umode_t mode", "setuid/setgid bits are a privilege-escalation vector"},
	{91, "fchmod", "unsigned int fd, umode_t mode", ""},
	{92, "chown", "const char *filename, uid_t user, gid_t group", ""},
	{95, "umask", "int mask", ""},
	{96, "gettimeofday", "struct timeval *tv, struct timezone *tz", ""},
	{97, "getrlimit", "unsigned int resource, struct rlimit *rlim", ""},
	{101, "ptrace", "long request, long pid, void *addr, void *data", "process inspection/injection; used by debuggers AND malware"},
	{102, "getuid", "", ""},
	{104, "getgid", "", ""},
	{105, "setuid", "uid_t uid", "privilege change; drop-or-gain root"},
	{106, "setgid", "gid_t gid", ""},
	{107, "geteuid", "", ""},
	{108, "getegid", "", ""},
	{110, "getppid", "", ""},
	{111, "getpgrp", "", ""},
	{126, "capset", "cap_user_header_t header, const cap_user_data_t data", "sets process capabilities; privilege manipulation"},
	{135, "personality", "unsigned int personality", "can disable ASLR (ADDR_NO_RANDOMIZE) to ease exploitation"},
	{137, "statfs", "const char *pathname, struct statfs *buf", ""},
	{155, "pivot_root", "const char *new_root, const char *put_old", "container root switch; sandbox/escape relevant"},
	{157, "prctl", "int option, unsigned long arg2, ...", "PR_SET_DUMPABLE / seccomp / no_new_privs toggles"},
	{158, "arch_prctl", "int code, unsigned long addr", ""},
	{165, "mount", "char *dev, char *dir, char *type, unsigned long flags, void *data", "filesystem mounts; container escape / overlay tricks"},
	{166, "umount2", "const char *target, int flags", ""},
	{169, "reboot", "int magic1, int magic2, unsigned int cmd, void *arg", "can halt/reboot the host"},
	{175, "init_module", "void *umod, unsigned long len, const char *uargs", "loads a kernel module — rootkit/LKM vector"},
	{176, "delete_module", "const char *name_user, unsigned int flags", "unloads a kernel module"},
	{186, "gettid", "", ""},
	{200, "tkill", "pid_t pid, int sig", ""},
	{201, "time", "time_t *tloc", ""},
	{202, "futex", "u32 *uaddr, int op, u32 val, ...", ""},
	{217, "getdents64", "unsigned int fd, struct linux_dirent64 *dirent, unsigned int count", ""},
	{218, "set_tid_address", "int *tidptr", ""},
	{228, "clock_gettime", "clockid_t which_clock, struct timespec *tp", ""},
	{230, "clock_nanosleep", "clockid_t which_clock, int flags, ...", ""},
	{231, "exit_group", "int error_code", ""},
	{232, "epoll_wait", "int epfd, struct epoll_event *events, int maxevents, int timeout", ""},
	{233, "epoll_ctl", "int epfd, int op, int fd, struct epoll_event *event", ""},
	{234, "tgkill", "pid_t tgid, pid_t pid, int sig", ""},
	{246, "kexec_load", "unsigned long entry, unsigned long nr_segments, ...", "loads a new kernel for kexec — host takeover vector"},
	{247, "waitid", "int which, pid_t upid, struct siginfo *infop, int options, ...", ""},
	{248, "add_key", "const char *type, const char *desc, const void *payload, ...", "kernel keyring; credential storage"},
	{250, "keyctl", "int cmd, unsigned long arg2, ...", "kernel keyring control"},
	{257, "openat", "int dfd, const char *filename, int flags, umode_t mode", ""},
	{262, "newfstatat", "int dfd, const char *filename, struct stat *statbuf, int flag", ""},
	{263, "unlinkat", "int dfd, const char *pathname, int flag", ""},
	{266, "symlinkat", "const char *oldname, int newdfd, const char *newname", ""},
	{267, "readlinkat", "int dfd, const char *pathname, char *buf, int bufsiz", ""},
	{269, "fchmodat", "int dfd, const char *filename, umode_t mode", ""},
	{270, "faccessat", "int dfd, const char *filename, int mode", ""},
	{272, "unshare", "unsigned long unshare_flags", "creates new namespaces; container/sandbox relevant"},
	{273, "set_robust_list", "struct robust_list_head *head, size_t len", ""},
	{280, "utimensat", "int dfd, const char *filename, struct timespec *utimes, int flags", "timestomping — anti-forensics indicator"},
	{288, "accept4", "int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags", ""},
	{291, "epoll_create1", "int flags", ""},
	{292, "dup3", "unsigned int oldfd, unsigned int newfd, int flags", ""},
	{293, "pipe2", "int *fildes, int flags", ""},
	{302, "prlimit64", "pid_t pid, unsigned int resource, ...", ""},
	{308, "setns", "int fd, int nstype", "joins another process' namespace — container escape"},
	{310, "process_vm_readv", "pid_t pid, const struct iovec *lvec, ...", "reads another process' memory — credential theft"},
	{311, "process_vm_writev", "pid_t pid, const struct iovec *lvec, ...", "writes another process' memory — injection"},
	{313, "finit_module", "int fd, const char *uargs, int flags", "loads a kernel module from an fd — rootkit vector"},
	{317, "seccomp", "unsigned int op, unsigned int flags, void *uargs", "installs syscall filters; sandboxing primitive"},
	{318, "getrandom", "char *buf, size_t count, unsigned int flags", ""},
	{319, "memfd_create", "const char *name, unsigned int flags", "anonymous in-memory file — fileless execution vector"},
	{321, "bpf", "int cmd, union bpf_attr *attr, unsigned int size", "eBPF programs; powerful and abuse-prone"},
	{322, "execveat", "int dfd, const char *filename, const char *const argv[], ...", "exec via fd — pairs with memfd for fileless exec"},
	{332, "statx", "int dfd, const char *filename, unsigned flags, unsigned mask, struct statx *buffer", ""},
	{334, "rseq", "struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig", ""},
	{435, "clone3", "struct clone_args *uargs, size_t size", "modern clone; namespace flags → sandbox escapes"},
	{436, "close_range", "unsigned int first, unsigned int last, unsigned int flags", ""},
	{439, "faccessat2", "int dfd, const char *filename, int mode, int flags", ""},
	{441, "epoll_pwait2", "int epfd, struct epoll_event *events, int maxevents, ...", ""},
	{425, "io_uring_setup", "u32 entries, struct io_uring_params *p", "async I/O ring; can bypass some syscall-based monitoring"},
	{426, "io_uring_enter", "unsigned int fd, u32 to_submit, ...", ""},
	{427, "io_uring_register", "unsigned int fd, unsigned int op, ...", ""},
}

var (
	numIdx  map[int]scEnt
	nameIdx map[string]scEnt
)

func init() {
	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i].Num < syscalls[j].Num })
	numIdx = map[int]scEnt{}
	nameIdx = map[string]scEnt{}
	for _, s := range syscalls {
		numIdx[s.Num] = s
		nameIdx[s.Name] = s
	}
}

func trunc(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// ---------------------------------------------------------------------------
// Rendering helpers shared by TUI + CLI
// ---------------------------------------------------------------------------

func showEntry(s scEnt) {
	rows := [][]string{
		{"number", strconv.Itoa(s.Num)},
		{"name", s.Name},
		{"args", s.Args},
		{"arch", "x86_64 Linux"},
	}
	if s.notable() {
		rows = append(rows, []string{"security", s.Note})
	}
	table([]string{"Field", "Value"}, rows)
	if s.notable() {
		fmt.Println()
		warnMsg("security-notable syscall")
	}
}

func searchRows(q string) [][]string {
	q = strings.ToLower(q)
	rows := [][]string{}
	for _, s := range syscalls {
		if strings.Contains(s.Name, q) || strings.Contains(strings.ToLower(s.Args), q) {
			flag := ""
			if s.notable() {
				flag = col("●", OR)
			}
			rows = append(rows, []string{strconv.Itoa(s.Num), s.Name, trunc(s.Args, 42), flag})
		}
	}
	return rows
}

// ---------------------------------------------------------------------------
// Interactive handlers
// ---------------------------------------------------------------------------

func doLookupNum() {
	v := prompt("syscall number")
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		errMsg("not a number")
		pause()
		return
	}
	clear()
	banner()
	header("Syscall by number")
	if s, ok := numIdx[n]; ok {
		showEntry(s)
	} else {
		errMsg(fmt.Sprintf("syscall %d not in local table (%d entries)", n, len(syscalls)))
	}
	pause()
}

func doLookupName() {
	name := strings.ToLower(strings.TrimSpace(prompt("syscall name")))
	clear()
	banner()
	header("Syscall by name")
	if s, ok := nameIdx[name]; ok {
		showEntry(s)
	} else {
		rows := searchRows(name)
		if len(rows) == 0 {
			errMsg("not found")
		} else {
			info("Partial matches:")
			table([]string{"Num", "Name", "Args", "⚑"}, rows)
		}
	}
	pause()
}

func doBrowse() {
	clear()
	banner()
	header("Syscall table (x86_64)")
	info(fmt.Sprintf("%d syscalls in table   (● = security-notable)", len(syscalls)))
	rows := [][]string{}
	for _, s := range syscalls {
		flag := ""
		if s.notable() {
			flag = col("●", OR)
		}
		rows = append(rows, []string{strconv.Itoa(s.Num), s.Name, trunc(s.Args, 48), flag})
	}
	table([]string{"Num", "Name", "Args", "⚑"}, rows)
	pause()
}

func doSearch() {
	q := strings.ToLower(prompt("search substring"))
	clear()
	banner()
	header("Search: " + q)
	rows := searchRows(q)
	if len(rows) == 0 {
		warnMsg("no matches")
	} else {
		table([]string{"Num", "Name", "Args", "⚑"}, rows)
		info(fmt.Sprintf("%d match(es)", len(rows)))
	}
	pause()
}

func doNotable() {
	clear()
	banner()
	header("Security-notable syscalls")
	rows := [][]string{}
	for _, s := range syscalls {
		if s.notable() {
			rows = append(rows, []string{strconv.Itoa(s.Num), s.Name, trunc(s.Note, 52)})
		}
	}
	table([]string{"Num", "Name", "Why it matters"}, rows)
	info(fmt.Sprintf("%d flagged syscalls — common in exploit, malware or escape chains", len(rows)))
	pause()
}

// /proc/<pid>/syscall : "running" OR "<nr> <a0>..<a5> <sp> <ip>"
func readProcSyscall(pid string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", pid, "syscall"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func renderPidSyscall(pid, s string) {
	info("PID " + pid)
	info("raw: " + s)
	fmt.Println()
	if s == "running" {
		okMsg("Task is actively running in userspace (not blocked in a syscall)")
		return
	}
	fields := strings.Fields(s)
	if len(fields) < 1 {
		warnMsg("unexpected format")
		return
	}
	nr64, err := strconv.ParseInt(fields[0], 0, 64)
	if err != nil {
		errMsg(err.Error())
		return
	}
	name, args, note := "?", "", ""
	if e, ok := numIdx[int(nr64)]; ok {
		name, args, note = e.Name, e.Args, e.Note
	}
	rows := [][]string{{"nr", fields[0]}, {"name", name}, {"args", args}}
	if note != "" {
		rows = append(rows, []string{"security", note})
	}
	labels := []string{"a0", "a1", "a2", "a3", "a4", "a5", "sp", "ip"}
	for i := 1; i < len(fields) && i-1 < len(labels); i++ {
		rows = append(rows, []string{labels[i-1], fields[i]})
	}
	table([]string{"Field", "Value"}, rows)
}

func doPidSyscall() {
	pid := prompt("PID")
	s, err := readProcSyscall(pid)
	if err != nil {
		errMsg(err.Error())
		if os.Geteuid() != 0 {
			warnMsg("reading /proc/<pid>/syscall of other users usually needs root")
		}
		pause()
		return
	}
	clear()
	banner()
	header("/proc/" + pid + "/syscall")
	renderPidSyscall(pid, s)
	pause()
}

type scCount struct {
	k string
	v int
}

func sampleProc() (total, running, unknown int, counts map[string]int) {
	counts = map[string]int{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		s, err := readProcSyscall(e.Name())
		if err != nil {
			continue
		}
		total++
		if s == "running" {
			running++
			counts["(running)"]++
			continue
		}
		fields := strings.Fields(s)
		if len(fields) == 0 {
			continue
		}
		nr, err := strconv.ParseInt(fields[0], 0, 64)
		if err != nil {
			continue
		}
		if e2, ok := numIdx[int(nr)]; ok {
			counts[e2.Name]++
		} else {
			unknown++
			counts[fmt.Sprintf("nr=%d", nr)]++
		}
	}
	return
}

func doSummary() {
	clear()
	banner()
	header("System-wide /proc syscall summary")
	total, running, unknown, counts := sampleProc()
	var ks []scCount
	for k, v := range counts {
		ks = append(ks, scCount{k, v})
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].v != ks[j].v {
			return ks[i].v > ks[j].v
		}
		return ks[i].k < ks[j].k
	})
	info(fmt.Sprintf("Processes sampled: %d   running(userspace): %d   unknown-nr: %d", total, running, unknown))
	if total == 0 {
		warnMsg("no readable tasks (need /proc; other users' tasks usually need root)")
		pause()
		return
	}
	fmt.Println()
	rows := [][]string{}
	for i, x := range ks {
		if i >= 25 {
			break
		}
		rows = append(rows, []string{x.k, strconv.Itoa(x.v)})
	}
	table([]string{"Syscall / State", "Count"}, rows)
	pause()
}

// ---------------------------------------------------------------------------
// Interactive menu
// ---------------------------------------------------------------------------

func menu(title string, items [][2]string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it[0], 32), W) + col("─ "+it[1], DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}

func interactive() {
	for {
		c := menu("Main Menu", [][2]string{
			{"Lookup by number", "number → name, signature, note"},
			{"Lookup by name", "name → number (fuzzy fallback)"},
			{"Browse syscall table", "all entries, notable ones flagged"},
			{"Search syscalls", "substring over name + signature"},
			{"Security-notable syscalls", "exploit / malware / escape vectors"},
			{"Show /proc/<pid>/syscall", "what one task is blocked in now"},
			{"System-wide summary", "sample every task, rank syscalls"},
		})
		switch strings.ToLower(c) {
		case "1":
			doLookupNum()
		case "2":
			doLookupName()
		case "3":
			doBrowse()
		case "4":
			doSearch()
		case "5":
			doNotable()
		case "6":
			doPidSyscall()
		case "7":
			doSummary()
		case "h", "help", "?":
			tuiHelp()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("MODES")
	fmt.Println("    --num N            look up syscall by number")
	fmt.Println("    --name NAME        look up syscall by name")
	fmt.Println("    --search STR       substring search over name + signature")
	fmt.Println("    --list             print the whole table")
	fmt.Println("    --notable          print only the security-notable syscalls")
	fmt.Println("    --pid PID          show /proc/PID/syscall (what it is blocked in)")
	fmt.Println("    --summary          sample every /proc task and rank syscalls")
	fmt.Println()
	sec("OUTPUT")
	fmt.Println("    --no-color         disable ANSI colour")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    " + APPNAME + " --num 59")
	fmt.Println("    " + APPNAME + " --name execve")
	fmt.Println("    " + APPNAME + " --search socket")
	fmt.Println("    " + APPNAME + " --notable")
	fmt.Println("    " + APPNAME + " --pid 1")
	fmt.Println("    " + APPNAME + " --summary")
	fmt.Println()
	rule()
}

// ---------------------------------------------------------------------------
// Help (TUI)
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	out := []string{}
	cur := ""
	for _, w := range words {
		if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
			out = append(out, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	out = append(out, cur)
	return out
}
func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}
func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}
func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func tuiHelp() {
	clear()
	banner()
	rule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	rule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	rule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	usage()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OSyscall is a quick reference for Linux x86_64 system calls and a live view of what the running system is doing. The built-in table maps syscall numbers to names and C signatures, and flags the syscalls that matter for security (execve, ptrace, mount, bpf, memfd_create, init_module and friends) with a one-line note on why.",
	"It also reads /proc/<pid>/syscall to show which syscall a task is currently blocked in, and can sample every task to rank the syscalls the whole system is sitting in — useful for triage and for understanding a strace/seccomp profile.",
}
var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Lookups and searches work on the offline table and need no privileges. The /proc options read live kernel state; other users' tasks usually require root.",
	"Everything is also available from the command line (see page 2) for scripting.",
}
var owlHelpMenu = []owlHelpItem{
	{"1", "Lookup by number: enter a syscall number; shows its name, signature, arch and any security note."},
	{"2", "Lookup by name: enter a name; exact match shows full detail, otherwise a fuzzy substring list."},
	{"3", "Browse: the whole table in number order; a ● marks security-notable syscalls."},
	{"4", "Search: substring match over both the name and the C signature."},
	{"5", "Security-notable: just the flagged syscalls and why each one matters in exploit/malware/escape chains."},
	{"6", "Show /proc/<pid>/syscall: the single syscall a task is blocked in right now, with decoded arg registers."},
	{"7", "System-wide summary: sample every readable task and rank which syscalls (or (running)) they are in."},
}
var owlHelpTips = []owlHelpItem{
	{"*", "The table is a curated common subset of x86_64 unistd_64.h, not the full ~400 — it covers the ones you meet in reversing, tracing and triage."},
	{"*", "Numbers are x86_64-specific. Other architectures (arm64, x86-32) renumber syscalls; don't reuse these numbers there."},
	{"*", "/proc/<pid>/syscall of another user's process needs CAP_SYS_PTRACE (usually root). Your own processes are always readable."},
	{"*", "--summary is a cheap, snapshot-based alternative to strace for seeing where the system spends its blocking time."},
}

// ---------------------------------------------------------------------------
// Demo + self-test
// ---------------------------------------------------------------------------

func runDemo() {
	banner()
	header("Demo — notable syscalls + live self view")
	rows := [][]string{}
	for _, n := range []int{59, 101, 165, 319, 175} {
		if s, ok := numIdx[n]; ok {
			rows = append(rows, []string{strconv.Itoa(s.Num), s.Name, trunc(s.Note, 46)})
		}
	}
	table([]string{"Num", "Name", "Why it matters"}, rows)
	fmt.Println()
	pid := strconv.Itoa(os.Getpid())
	if s, err := readProcSyscall(pid); err == nil {
		info("This process (/proc/" + pid + "/syscall):")
		fmt.Println()
		renderPidSyscall(pid, s)
	}
}

func runSelfTest() int {
	banner()
	header("Self-Test — table integrity + /proc parsing")
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	// Known x86_64 syscall numbers.
	known := map[int]string{0: "read", 1: "write", 2: "open", 59: "execve", 60: "exit",
		257: "openat", 101: "ptrace", 165: "mount", 319: "memfd_create", 321: "bpf"}
	for n, want := range known {
		e, ok := numIdx[n]
		check(fmt.Sprintf("num %d == %s", n, want), ok && e.Name == want)
	}

	// Name index agrees with the number index.
	nameOK := true
	for _, s := range syscalls {
		if nameIdx[s.Name].Num != s.Num {
			nameOK = false
		}
	}
	check("name index consistent with number index", nameOK)

	// Table is sorted by number and has no duplicate numbers.
	sorted, dup := true, false
	seen := map[int]bool{}
	for i, s := range syscalls {
		if i > 0 && syscalls[i-1].Num > s.Num {
			sorted = false
		}
		if seen[s.Num] {
			dup = true
		}
		seen[s.Num] = true
	}
	check("table sorted by number", sorted)
	check("no duplicate syscall numbers", !dup)

	// Notable set is non-empty and execve is flagged.
	nnote := 0
	for _, s := range syscalls {
		if s.notable() {
			nnote++
		}
	}
	check("has security-notable entries", nnote > 0)
	check("execve flagged notable", numIdx[59].notable())

	// /proc/<pid>/syscall parser on our own PID (should not error).
	pid := strconv.Itoa(os.Getpid())
	_, err := readProcSyscall(pid)
	check("read own /proc/<pid>/syscall", err == nil)

	// Search finds a known name.
	check("search 'socket' finds entries", len(searchRows("socket")) > 0)

	fmt.Println()
	rule()
	info(fmt.Sprintf("table entries: %d   notable: %d", len(syscalls), nnote))
	if fail == 0 {
		okMsg(fmt.Sprintf("ALL %d CHECKS PASSED", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ---------------------------------------------------------------------------

func printList(onlyNotable bool) {
	banner()
	if onlyNotable {
		header("Security-notable syscalls")
	} else {
		header("Syscall table (x86_64)")
	}
	rows := [][]string{}
	for _, s := range syscalls {
		if onlyNotable && !s.notable() {
			continue
		}
		flag := ""
		if s.notable() {
			flag = "●"
		}
		rows = append(rows, []string{strconv.Itoa(s.Num), s.Name, trunc(s.Args, 46), flag})
	}
	table([]string{"Num", "Name", "Args", "⚑"}, rows)
}

func main() {
	var (
		fNum     = flag.Int("num", -1, "")
		fName    = flag.String("name", "", "")
		fSearch  = flag.String("search", "", "")
		fList    = flag.Bool("list", false, "")
		fNotable = flag.Bool("notable", false, "")
		fPid     = flag.String("pid", "", "")
		fSummary = flag.Bool("summary", false, "")
		fNoCol   = flag.Bool("no-color", false, "")
		fDemo    = flag.Bool("demo", false, "")
		fSelf    = flag.Bool("selftest", false, "")
		fVerN    = flag.Bool("version", false, "")
	)
	flag.Usage = usage
	flag.Parse()
	if *fNoCol {
		noColor = true
	}
	switch {
	case *fVerN:
		fmt.Printf("%s %s  (OWL suite — %s / %s)\n", APPNAME, VERSION, AUTHOR, WEBSITE)
		return
	case *fSelf:
		os.Exit(runSelfTest())
	case *fDemo:
		runDemo()
		return
	case *fNum >= 0:
		banner()
		header("Syscall by number")
		if s, ok := numIdx[*fNum]; ok {
			showEntry(s)
		} else {
			errMsg(fmt.Sprintf("syscall %d not in table", *fNum))
			os.Exit(1)
		}
	case *fName != "":
		banner()
		header("Syscall by name")
		if s, ok := nameIdx[strings.ToLower(*fName)]; ok {
			showEntry(s)
		} else {
			rows := searchRows(strings.ToLower(*fName))
			if len(rows) == 0 {
				errMsg("not found")
				os.Exit(1)
			}
			table([]string{"Num", "Name", "Args", "⚑"}, rows)
		}
	case *fSearch != "":
		banner()
		header("Search: " + *fSearch)
		rows := searchRows(*fSearch)
		if len(rows) == 0 {
			warnMsg("no matches")
			os.Exit(1)
		}
		table([]string{"Num", "Name", "Args", "⚑"}, rows)
	case *fNotable:
		printList(true)
	case *fList:
		printList(false)
	case *fPid != "":
		s, err := readProcSyscall(*fPid)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		banner()
		header("/proc/" + *fPid + "/syscall")
		renderPidSyscall(*fPid, s)
	case *fSummary:
		doSummaryCLI()
	default:
		interactive()
	}
}

func doSummaryCLI() {
	banner()
	header("System-wide /proc syscall summary")
	total, running, unknown, counts := sampleProc()
	var ks []scCount
	for k, v := range counts {
		ks = append(ks, scCount{k, v})
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].v != ks[j].v {
			return ks[i].v > ks[j].v
		}
		return ks[i].k < ks[j].k
	})
	info(fmt.Sprintf("Processes sampled: %d   running(userspace): %d   unknown-nr: %d", total, running, unknown))
	rows := [][]string{}
	for i, x := range ks {
		if i >= 25 {
			break
		}
		rows = append(rows, []string{x.k, strconv.Itoa(x.v)})
	}
	table([]string{"Syscall / State", "Count"}, rows)
}
