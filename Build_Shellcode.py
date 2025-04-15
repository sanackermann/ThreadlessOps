import subprocess
import os

print("Step 1: Running 'make' in the 'Shellcode' folder...")
result = subprocess.run(["make"], cwd="Shellcode", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

# Check if there was an error during 'make' and print the error if it exists
if result.returncode != 0:
    print("Error during 'make':")
    print(result.stderr.decode())

print("Step 2: Extract the code...")
command = """for i in $(objdump -d Shellcode/Shellcode.exe | grep "^ " | cut -f2); do printf "\\x$i"; done"""
output = subprocess.check_output(command, shell=True, universal_newlines=True)

print("Step 3: Write the binary...")
hex_string = output.replace('\\x', '').replace(' ', '').strip()
binary_data = bytes.fromhex(hex_string)
data_size = len(binary_data)
if data_size > 1024:
    data_size_kb = data_size / 1024
    print(f"Binary data size: {data_size_kb:.2f} KB")
else:
    print(f"Binary data size: {data_size} bytes")
with open('Shellcode.bin', 'wb') as bin_file:
    bin_file.write(binary_data)
with open('Shellcode.bin', 'wb') as bin_file:
    bin_file.write(binary_data)


print("Process completed successfully. 'Shellcode.bin' has been created.")
