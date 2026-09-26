#!/usr/bin/env python3
"""Generates `keccak3_aarch64.rs`, the AArch64 Keccak-p[1600, 24] kernel for
three states: two in the halves of NEON vectors (SHA3-extension
instructions) and one on the general-purpose registers, as one `asm!` block
with the two instruction streams interleaved round by round.

Run from the repository root: `python3 src/keccak/keccak3_aarch64.py`. The
script checks the whole generated program against a reference permutation on
random states before writing the file; the crate's tests check it again.

- Vector state: lane `i` of both vector states lives in `v{i}`; each round
  uses `v25..v31` as temporaries and ends with the lanes back in `v0..v24`,
  so every round is the same instruction sequence (`VECTOR_ROUND`).
- Scalar state: the lazy-rotation round of `keccak_soft.rs` (each lane is
  kept rotated right by a pending offset, `LAZY[k]` before round `k`, so
  every rotation is the shifted operand of an `eor`/`bic`). Its values are
  given 26 registers by Belady's farthest-next-use rule, spilling the rest
  to eight stack slots the block allocates below the stack pointer and
  wipes before releasing (measured faster than a Rust-side buffer passed
  by pointer; giving the freed pointer register to the allocator measured
  slower).
- The rounds' vector and scalar instructions are merged in proportion, and
  the round constants are read through one pointer: the vector constant,
  then the scalar one (rotated right by lane 0's pending offset).
- The block loops `ITERATIONS` times over `BODY_ROUNDS` rounds, after which
  each scalar lane is rotated by its pending offset into register `i` (one
  `ror` each, a spare register breaking cycles), so every pass starts from
  the same registers and offsets. The unrolled 24 rounds (17.6 KB of code,
  with more instruction-cache misses) measured slower than this 6 KB loop in
  ML-KEM and X-Wing. The pass count is kept in the stack word after the
  spill slots.
"""

import random

M = (1 << 64) - 1
ROUNDS = 24
BODY_ROUNDS = 8
ITERATIONS = ROUNDS // BODY_ROUNDS
SCALAR_REGS = 26
SPILL_WORDS = 8
# The block's stack frame: the spill slots and the pass counter, rounded up
# to the 16 bytes the stack pointer must stay aligned to.
FRAME_BYTES = (8 * (SPILL_WORDS + 1) + 15) // 16 * 16

RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & M if n else v


def pi_dest(i):
    x, y = i % 5, i // 5
    return y + 5 * ((2 * x + 3 * y) % 5)


# Pending right rotations of the scalar lanes before each round of a pass
# (the `LAZY` table of `keccak_soft.rs`).
LAZY = [[0] * 25]
for _ in range(BODY_ROUNDS):
    p = [0] * 25
    for i in range(25):
        p[pi_dest(i)] = (LAZY[-1][i] + RHO[i]) % 64
    LAZY.append(p)


def reference(state):
    a = list(state)
    for rc in RC[24 - ROUNDS:]:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
        b = [0] * 25
        for i in range(25):
            b[pi_dest(i)] = rol(a[i] ^ d[i % 5], RHO[i])
        a = [b[j] ^ (~b[j - j % 5 + (j + 1) % 5] & M & b[j - j % 5 + (j + 2) % 5]) for j in range(25)]
        a[0] ^= rc
    return a


def vector_round_attempt(rnd):
    """One round on `v0..v24` with temporaries `v25..v31`, or `None` when the
    random choices of rho-pi destinations run out of registers."""
    ops = []
    # Rows 2 to 4 first: chi below writes rows 4 down to 0, so the next
    # round's first half of theta can start before chi finishes.
    for x in range(5):
        ops.append(("eor3", 25 + x, x + 10, x + 15, x + 20))
    for x in range(5):
        ops.append(("eor3", 25 + x, 25 + x, x, x + 5))
    dreg = {1: 30, 2: 31, 3: 27, 4: 28, 0: 29}
    for x in (1, 2, 3, 4, 0):
        ops.append(("rax1", dreg[x], 25 + (x - 1) % 5, 25 + (x + 1) % 5))
    free = {25, 26}
    d_uses = {x: 5 for x in range(5)}
    a_reg = {i: i for i in range(25)}
    b_reg = {}
    todo = list(range(25))

    def allowed(j):
        # Row `y` of `B` goes to the registers of row `y - 1`, row 0 to the
        # temporaries, so chi can write each row back in place.
        y = j // 5
        return set(range(25, 32)) if y == 0 else set(range(5 * (y - 1), 5 * y))

    while todo:
        cand = []
        for i in todo:
            avail = set(free) | {a_reg[i]}
            if d_uses[i % 5] == 1:
                avail.add(dreg[i % 5])
            t = avail & allowed(pi_dest(i))
            if t:
                cand.append((i, sorted(t)))
        if not cand:
            return None
        i, t = rnd.choice(cand)
        dst = rnd.choice(t)
        x = i % 5
        if i == 0:
            ops.append(("eor", dst, a_reg[0], dreg[0]))
        else:
            ops.append(("xar", dst, a_reg[i], dreg[x], (64 - RHO[i]) % 64))
        free.add(a_reg.pop(i))
        d_uses[x] -= 1
        if d_uses[x] == 0:
            free.add(dreg[x])
        free.discard(dst)
        b_reg[pi_dest(i)] = dst
        todo.remove(i)
    rc_reg = min(set(range(25, 32)) - set(b_reg.values()))
    ops.append(("ld1r", rc_reg))
    for y in (4, 3, 2, 1, 0):
        for x in range(5):
            b = [b_reg[5 * y + (x + k) % 5] for k in range(3)]
            ops.append(("bcax", 5 * y + x, b[0], b[2], b[1]))
    ops.append(("eor", 0, 0, rc_reg))
    return ops


def run_vector_round(ops, state, rc):
    reg = list(state) + [0] * 7
    for op in ops:
        k = op[0]
        if k == "eor3":
            reg[op[1]] = reg[op[2]] ^ reg[op[3]] ^ reg[op[4]]
        elif k == "eor":
            reg[op[1]] = reg[op[2]] ^ reg[op[3]]
        elif k == "rax1":
            reg[op[1]] = reg[op[2]] ^ rol(reg[op[3]], 1)
        elif k == "ld1r":
            reg[op[1]] = rc
        elif k == "xar":
            reg[op[1]] = rol(reg[op[2]] ^ reg[op[3]], 64 - op[4])
        elif k == "bcax":
            reg[op[1]] = reg[op[2]] ^ (reg[op[3]] & ~reg[op[4]] & M)
    return reg[:25]


def vector_round():
    """The first attempt (by seed) that computes a correct round."""
    rr = random.Random(1)
    state = [rr.getrandbits(64) for _ in range(25)]
    for seed in range(2000):
        ops = vector_round_attempt(random.Random(seed))
        if ops is None:
            continue
        a = reference_round(state, RC[3])
        if run_vector_round(ops, state, RC[3]) == a:
            return ops
    raise RuntimeError("no vector schedule")


def reference_round(state, rc):
    c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
    d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
    b = [0] * 25
    for i in range(25):
        b[pi_dest(i)] = rol(state[i] ^ d[i % 5], RHO[i])
    a = [b[j] ^ (~b[j - j % 5 + (j + 1) % 5] & M & b[j - j % 5 + (j + 2) % 5]) for j in range(25)]
    a[0] ^= rc
    return a


def scalar_values():
    """One pass of scalar rounds as single-assignment operations on value numbers:
    `("xr", d, s, t, n)` is `d = s ^ rotl(t, n)`, `("br", ...)` is
    `d = s & !rotl(t, n)`, `("rc", d, k)` loads round `k`'s scalar constant
    and `("x0", d, s, t)` is `d = s ^ t`. Returns the operations with the
    initial and final lane values."""
    count = [0]

    def new():
        count[0] += 1
        return count[0]

    a = [new() for _ in range(25)]
    initial = list(a)
    ops = []
    src_of = {pi_dest(i): i for i in range(25)}
    for k in range(BODY_ROUNDS):
        p, q = LAZY[k], LAZY[k + 1]
        c = []
        for x in range(5):
            t1 = new()
            ops.append(("xr", t1, a[x], a[x + 5], (p[x + 5] - p[x]) % 64))
            t2 = new()
            ops.append(("xr", t2, a[x + 10], a[x + 15], (p[x + 15] - p[x + 10]) % 64))
            t3 = new()
            ops.append(("xr", t3, t1, t2, (p[x + 10] - p[x]) % 64))
            c.append(new())
            ops.append(("xr", c[x], t3, a[x + 20], (p[x + 20] - p[x]) % 64))
        d = []
        for x in range(5):
            d.append(new())
            l, r = (x - 1) % 5, (x + 1) % 5
            ops.append(("xr", d[x], c[l], c[r], (p[r] + 1 - p[l]) % 64))
        b = [None] * 25
        new_a = [None] * 25
        for y in range(5):
            for x in range(5):
                j = 5 * y + x
                i = src_of[j]
                b[j] = new()
                ops.append(("xr", b[j], a[i], d[i % 5], (p[(i - 1) % 5] - p[i]) % 64))
            for x in range(5):
                j = 5 * y + x
                j1, j2 = 5 * y + (x + 1) % 5, 5 * y + (x + 2) % 5
                t = new()
                ops.append(("br", t, b[j2], b[j1], (q[j1] - q[j2]) % 64))
                new_a[j] = new()
                ops.append(("xr", new_a[j], b[j], t, (q[j2] - q[j]) % 64))
        rc = new()
        ops.append(("rc", rc, k))
        a0 = new()
        ops.append(("x0", a0, new_a[0], rc))
        new_a[0] = a0
        a = new_a
    return ops, initial, a


def scalar_rc(r):
    """Round `r`'s constant, rotated right by lane 0's pending offset."""
    return rol(RC[24 - ROUNDS + r], 64 - LAZY[r % BODY_ROUNDS + 1][0])


def allocate(ops, initial, final):
    """Assigns registers `0..SCALAR_REGS` (initial lane `i` in register `i`)
    and spill slots. Returns the per-round instruction lists (a round ends
    with its constant's load), the trailing reloads, and the final register
    of every lane."""
    uses = {}
    for idx, op in enumerate(ops):
        if op[0] in ("xr", "br", "x0"):
            for v in op[2:4]:
                uses.setdefault(v, []).append(idx)
    for v in final:
        uses.setdefault(v, []).append(len(ops))
    never = 1 << 60

    def next_use(v, idx):
        for u in uses.get(v, ()):
            if u >= idx:
                return u
        return never

    reg_of, slot_of = {}, {}
    holder = [None] * SCALAR_REGS
    free_slots = list(range(SPILL_WORDS))
    for i, v in enumerate(initial):
        reg_of[v] = i
        holder[i] = v
    out = []

    def take_reg(idx, protect):
        for r in range(SCALAR_REGS):
            if holder[r] is None:
                return r
        victim = max(
            (r for r in range(SCALAR_REGS) if holder[r] not in protect),
            key=lambda r: next_use(holder[r], idx),
        )
        v = holder[victim]
        if next_use(v, idx) < never and v not in slot_of:
            slot_of[v] = min(free_slots)
            free_slots.remove(slot_of[v])
            out.append(("st", victim, slot_of[v]))
        holder[victim] = None
        del reg_of[v]
        return victim

    def ensure(v, idx, protect):
        if v not in reg_of:
            r = take_reg(idx, protect)
            out.append(("ld", r, slot_of[v]))
            reg_of[v] = r
            holder[r] = v
        return reg_of[v]

    def release_dead(idx):
        for r in range(SCALAR_REGS):
            v = holder[r]
            if v is not None and next_use(v, idx) == never:
                holder[r] = None
                del reg_of[v]
                if v in slot_of:
                    free_slots.append(slot_of.pop(v))

    for idx, op in enumerate(ops):
        if op[0] == "rc":
            r = take_reg(idx, set())
            out.append(("rc", r, op[2]))
        else:
            s = ensure(op[2], idx, {op[2], op[3]})
            t = ensure(op[3], idx, {op[2], op[3]})
            release_dead(idx + 1)
            r = take_reg(idx + 1, set())
            out.append((op[0], r, s, t, op[4] if op[0] != "x0" else 0))
        reg_of[op[1]] = r
        holder[r] = op[1]
    for v in final:
        ensure(v, len(ops), set(final))
    rounds, current = [], []
    for ins in out:
        current.append(ins)
        if ins[0] == "rc":
            rounds.append(current)
            current = []
    return rounds, current, [reg_of[v] for v in final]


def normalize(final_regs):
    """Rotates lane `i` from `final_regs[i]` by its pending offset into
    register `i`: a parallel move, a spare register breaking cycles."""
    spare = next(r for r in range(25, SCALAR_REGS) if r not in final_regs)
    pending = {i: (final_regs[i], LAZY[BODY_ROUNDS][i]) for i in range(25)}
    out = []
    for i, (s, n) in list(pending.items()):
        if s == i:
            if n:
                out.append(("rr", i, i, n))
            del pending[i]
    while pending:
        sources = {s for s, _ in pending.values()}
        ready = [d for d in pending if d not in sources]
        if ready:
            s, n = pending.pop(ready[0])
            out.append(("rr", ready[0], s, n))
        else:
            d = next(iter(pending))
            s, n = pending[d]
            out.append(("rr", spare, s, n))
            pending[d] = (spare, 0)
    return out


def merge(vector, scalar):
    """Interleaves one round's vector and scalar instructions in proportion,
    the scalar stream a twentieth of a round ahead (measured best on
    Neoverse V3 in ML-KEM, between a tenth ahead and level), and the vector
    constant's load before the scalar one."""
    items = [(i / len(vector), 0, ("v", op)) for i, op in enumerate(vector)]
    items += [((i + 0.5) / len(scalar) - 0.05, 1, ("s", ins)) for i, ins in enumerate(scalar)]
    items.sort(key=lambda t: (t[0], t[1]))
    merged = [t[2] for t in items]
    vi = next(i for i, (kind, op) in enumerate(merged) if kind == "v" and op[0] == "ld1r")
    si = next(i for i, (kind, op) in enumerate(merged) if kind == "s" and op[0] == "rc")
    assert vi < si
    return merged


def text(item):
    kind, op = item
    k = op[0]
    if kind == "v":
        if k == "eor3":
            return f"eor3 v{op[1]}.16b, v{op[2]}.16b, v{op[3]}.16b, v{op[4]}.16b"
        if k == "eor":
            return f"eor v{op[1]}.16b, v{op[2]}.16b, v{op[3]}.16b"
        if k == "rax1":
            return f"rax1 v{op[1]}.2d, v{op[2]}.2d, v{op[3]}.2d"
        if k == "xar":
            return f"xar v{op[1]}.2d, v{op[2]}.2d, v{op[3]}.2d, #{op[4]}"
        if k == "bcax":
            return f"bcax v{op[1]}.16b, v{op[2]}.16b, v{op[3]}.16b, v{op[4]}.16b"
        if k == "ld1r":
            return f"ld1r {{{{v{op[1]}.2d}}}}, [{{rc}}], #8"
    if k == "xr":
        return f"eor {{r{op[1]}}}, {{r{op[2]}}}, {{r{op[3]}}}, ror #{(64 - op[4]) % 64}"
    if k == "br":
        return f"bic {{r{op[1]}}}, {{r{op[2]}}}, {{r{op[3]}}}, ror #{(64 - op[4]) % 64}"
    if k == "x0":
        return f"eor {{r{op[1]}}}, {{r{op[2]}}}, {{r{op[3]}}}"
    if k == "rc":
        return f"ldr {{r{op[1]}}}, [{{rc}}], #8"
    if k == "ld":
        return f"ldr {{r{op[1]}}}, [sp, #{8 * op[2]}]"
    if k == "st":
        return f"str {{r{op[1]}}}, [sp, #{8 * op[2]}]"
    if k == "rr":
        return f"ror {{r{op[1]}}}, {{r{op[2]}}}, #{(64 - op[3]) % 64}"
    if k == "label":
        return "2:"
    if k == "count":
        # The pass counter, decremented through register `r25` (free once
        # the lanes are back in `r0..r24`).
        return (f"ldr {{r25}}, [sp, #{8 * SPILL_WORDS}]\\n"
                f"subs {{r25}}, {{r25}}, #1\\n"
                f"str {{r25}}, [sp, #{8 * SPILL_WORDS}]\\n"
                "b.ne 2b")
    if k == "enter":
        # The frame, and the pass count through `r25` (free: the lanes start
        # in `r0..r24`).
        return (f"sub sp, sp, #{FRAME_BYTES}\\n"
                f"mov {{r25}}, #{ITERATIONS}\\n"
                f"str {{r25}}, [sp, #{8 * SPILL_WORDS}]")
    if k == "leave":
        # Wipes the frame (the spilled words are state-derived), then
        # releases it.
        wipe = "".join(f"stp xzr, xzr, [sp, #{o}]\\n" for o in range(0, FRAME_BYTES, 16))
        return wipe + f"add sp, sp, #{FRAME_BYTES}"
    raise ValueError(op)


def execute(program, a, b, c, table):
    """Runs the looped program (the vector halves as two scalar machines)."""
    va, vb = list(a) + [0] * 7, list(b) + [0] * 7
    reg = list(c) + [0] * (SCALAR_REGS - 25)
    spill = [0] * (SPILL_WORDS + 1)
    pos = 0
    pc = 0
    label = next(i for i, (_, op) in enumerate(program) if op[0] == "label")
    while pc < len(program):
        kind, op = program[pc]
        pc += 1
        k = op[0]
        if kind == "v":
            for v in (va, vb):
                if k == "eor3":
                    v[op[1]] = v[op[2]] ^ v[op[3]] ^ v[op[4]]
                elif k == "eor":
                    v[op[1]] = v[op[2]] ^ v[op[3]]
                elif k == "rax1":
                    v[op[1]] = v[op[2]] ^ rol(v[op[3]], 1)
                elif k == "xar":
                    v[op[1]] = rol(v[op[2]] ^ v[op[3]], 64 - op[4])
                elif k == "bcax":
                    v[op[1]] = v[op[2]] ^ (v[op[3]] & ~v[op[4]] & M)
                elif k == "ld1r":
                    v[op[1]] = table[pos]
            if k == "ld1r":
                pos += 1
        elif k == "xr":
            reg[op[1]] = reg[op[2]] ^ rol(reg[op[3]], op[4])
        elif k == "br":
            reg[op[1]] = reg[op[2]] & ~rol(reg[op[3]], op[4]) & M
        elif k == "x0":
            reg[op[1]] = reg[op[2]] ^ reg[op[3]]
        elif k == "rc":
            reg[op[1]] = table[pos]
            pos += 1
        elif k == "ld":
            reg[op[1]] = spill[op[2]]
        elif k == "st":
            spill[op[2]] = reg[op[1]]
        elif k == "rr":
            reg[op[1]] = rol(reg[op[2]], op[3])
        elif k == "enter":
            reg[25] = spill[SPILL_WORDS] = ITERATIONS
        elif k == "leave":
            spill = None
        elif k == "count":
            spill[SPILL_WORDS] -= 1
            reg[25] = spill[SPILL_WORDS]
            if spill[SPILL_WORDS] != 0:
                pc = label
    assert pos == len(table)
    return va[:25], vb[:25], reg[:25]


def rust(program, table):
    lines = []
    w = lines.append
    w("//! Keccak-p[1600, 24] on three states at once on AArch64 with the SHA3")
    w("//! extension: two in the halves of NEON vectors, one on the")
    w("//! general-purpose registers, interleaved round by round in one `asm!`")
    w("//! block so the scalar state runs on the integer pipes the vector rounds")
    w("//! leave idle (on Neoverse V3 the three cost about as much as the two-state")
    w("//! vector kernel alone).")
    w("//!")
    w("//! GENERATED by `keccak3_aarch64.py` (see there for the schedule and the")
    w("//! register allocation); do not edit by hand. The scalar state uses the")
    w("//! lazy rotations of `keccak_soft.rs`, with its values kept in 26")
    w("//! registers and eight stack slots; the block loops three times")
    w("//! over eight rounds.")
    w("")
    w("use core::arch::aarch64::{uint64x2_t, vcombine_u64, vcreate_u64, vgetq_lane_u64};")
    w("")
    w("use crate::aarch64::Sha3;")
    w("")
    w("/// For each round, the vector round constant, then the scalar one rotated")
    w("/// right by lane 0's pending rotation after the round.")
    w(f"static RC: [u64; {len(table)}] = [")
    for t in table:
        w(f"    0x{t:016x},")
    w("];")
    w("")
    w("/// Keccak-p[1600, 24] on `a` and `b` (the low and high vector halves) and")
    w("/// `c` (the general-purpose registers), in place.")
    w('#[target_feature(enable = "neon,sha3")]')
    w("fn permute3_unchecked(a: &mut [u64; 25], b: &mut [u64; 25], c: &mut [u64; 25]) {")
    for i in range(25):
        w(f"    let mut v{i}: uint64x2_t = vcombine_u64(vcreate_u64(a[{i}]), vcreate_u64(b[{i}]));")
    w("    let [")
    for i in range(25):
        w(f"        mut r{i},")
    w("    ] = *c;")
    for i in range(25, SCALAR_REGS):
        w(f"    let mut r{i} = 0u64;")
    w("    // SAFETY: the block only reads the constant table through `rc`")
    w(f"    // (advanced 8 bytes by each of its {len(table)} loads over the {ITERATIONS} passes,")
    w(f"    // exactly `RC`) and its own {FRAME_BYTES}-byte stack frame: it moves the stack")
    w("    // pointer down by that (keeping it 16-byte aligned), reads and writes")
    w(f"    // only below the old stack pointer (offsets below {8 * (SPILL_WORDS + 1)} bytes), wipes the")
    w("    // frame and restores the stack pointer before it ends. The loop runs")
    w(f"    // exactly the {ITERATIONS} passes counted in the frame. Every register it writes")
    w("    // is an output operand (`v0..v31`, the `r*` state registers and `rc`).")
    w("    unsafe {")
    w("        core::arch::asm!(")
    for item in program:
        w(f'            "{text(item)}",')
    w("            rc = inout(reg) RC.as_ptr() => _,")
    for i in range(SCALAR_REGS):
        w(f"            r{i} = inout(reg) r{i},")
    for i in range(25):
        w(f'            inout("v{i}") v{i},')
    for i in range(25, 32):
        w(f'            out("v{i}") _,')
    w("        );")
    w("    }")
    for i in range(25):
        w(f"    a[{i}] = vgetq_lane_u64::<0>(v{i});")
        w(f"    b[{i}] = vgetq_lane_u64::<1>(v{i});")
    w("    *c = [")
    w("        " + " ".join(f"r{i}," for i in range(20)))
    w("        " + " ".join(f"r{i}," for i in range(20, 25)))
    w("    ];")
    spare = [f"r{i}" for i in range(25, SCALAR_REGS)]
    w(f"    let _ = ({spare[0]},);" if len(spare) == 1 else f"    let _ = ({', '.join(spare)});")
    w("}")
    w("")
    w("/// [`permute3_unchecked`], safe to call with a [`Sha3`] token.")
    w("#[inline(always)]")
    w("pub(super) fn permute3(_: Sha3, a: &mut [u64; 25], b: &mut [u64; 25], c: &mut [u64; 25]) {")
    w("    // SAFETY: a `Sha3` token exists only after detection of `sha3`, which")
    w("    // implies the `neon` the kernel is also compiled for.")
    w("    unsafe { permute3_unchecked(a, b, c) }")
    w("}")
    return "\n".join(lines) + "\n"


def main():
    vector = vector_round()
    ops, initial, final = scalar_values()
    rounds, tail, final_regs = allocate(ops, initial, final)
    program = [("s", ("enter",)), ("s", ("label",))]
    for k in range(BODY_ROUNDS):
        program += merge(vector, rounds[k])
    program += [("s", ins) for ins in tail + normalize(final_regs) + [("count",), ("leave",)]]
    table = []
    for r in range(ROUNDS):
        table += [RC[24 - ROUNDS + r], scalar_rc(r)]
    rr = random.Random(0x6b656363616b33)
    for _ in range(8):
        a, b, c = ([rr.getrandbits(64) for _ in range(25)] for _ in range(3))
        assert execute(program, a, b, c, table) == (reference(a), reference(b), reference(c))
    path = __file__.replace(".py", ".rs")
    with open(path, "w") as f:
        f.write(rust(program, table))
    print(f"{path}: {len(program)} instructions")


if __name__ == "__main__":
    main()
