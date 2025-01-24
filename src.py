import struct

with open("./test", "rb") as f: 
    # Read the ELF header (first 64 bytes for 64-bit ELF)
    e_ident = f.read(16) 
    if e_ident[:4] != b"\x7fELF": 
        raise ValueError("Not an ELF file") 

    # Parse ELF class (32-bit or 64-bit)
    elf_class = e_ident[4]
    if elf_class == 1:
        elf_type = "ELF32"
        header_format = "<HHIIIIIHHHHHH"  # 32-bit ELF header structure
    elif elf_class == 2:
        elf_type = "ELF64"
        header_format = "<HHIQQQIHHHHHH"  # 64-bit ELF header structure
    else:
        raise ValueError("Unknown ELF class")
    
    elf_data = e_ident[5]
    if elf_data == 1:
        elf_data = "Little Edian"
    elif elf_data == 2:
        elf_data = "Big Edian"
    else:
        raise ValueError("Unknown ELF data")
    
    elf_version = e_ident[6]

    osabi_mapping = {
        0x00: "System V",
        0x01: "HP-UX",
        0x02: "NetBSD",
        0x03: "Linux",
        0x04: "GNU Hurd",
        0x06: "Solaris",
        0x07: "AIX",
        0x08: "IRIX",
        0x09: "FreeBSD",
        0x0A: "Tru64",
        0x0B: "Novell Modesto",
        0x0C: "OpenBSD",
        0x0D: "OpenVMS",
        0x0E: "NonStop Kernel",
        0x0F: "AROS",
        0x10: "FenixOS",
        0x11: "Nuxi CloudABI",
        0x12: "Stratus Technologies OpenVOS"
    }
    elf_osabi = e_ident[7] 
    osabi_name = osabi_mapping.get(elf_osabi)
        
    # Read the rest of the ELF header
    header_size = struct.calcsize(header_format)
    header = f.read(header_size)

    # Unpack ELF header
    fields = struct.unpack(header_format, header)

    print("ELF Header:")
    print("=" * 45)
    print(f"{'Class:':<35} {elf_type}")
    print(f"{'Data:':<35} {elf_data}")
    print(f"{'Version:':<35} {elf_version}")
    print(f"{'OS/ABI:':<35} {osabi_name}")

    header_info = {
        "Type:": fields[0],
        "Machine:": fields[1],
        "Version:": fields[2],
        "Entry point address:": fields[3],
        "Start of program headers:": fields[4],
        "Start of section headers:": fields[5],
        "Flags:": fields[6],
        "Size of this header:": fields[7],
        "Size of program headers:": fields[8],
        "Number of program headers:": fields[9],
        "Size of section headers:": fields[10],
        "Number of section headers:": fields[11],
        "Section header string table index:": fields[12],
    }

    # Print ELF Header information
    for key, value in header_info.items():
        print(f"{key:<35} {hex(value):<10}")

    # Read ELF Segment
    ph_offset = fields[4]   # e_phoff: Start of program headers
    ph_entry_size = fields[8]  # e_phentsize: Size of each program header
    ph_num = fields[9]         # e_phnum: Number of program headers
    ph_entry_format = "<IIQQQQQQ"      # 64-bit Program Header

    print(f"\nProgram Headers (Offset: {ph_offset}, Entries: {ph_num}):")
    print(f"{'Type':<15} {'Offset':<10} {'VirtAddr':<18} {'PhysAddr':<18} {'FileSize':<10} {'MemSize':<10} {'Flags':<8} {'Align':<10}")
    print("=" * 100)

    for i in range(ph_num):
        entry_data = f.read(ph_entry_size)
        ph_fields = struct.unpack(ph_entry_format, entry_data)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph_fields

        # Map p_type to readable names
        p_type_mapping = {
            0: "NULL",
            1: "LOAD",
            2: "DYNAMIC",
            3: "INTERP",
            4: "NOTE",
            5: "SHLIB",
            6: "PHDR",
            7: "TLS",
            0x6474e550: "GNU_EH_FRAME",
            0x6474e551: "GNU_STACK",
            0x6474e552: "GNU_RELRO"
        }
        p_type_name = p_type_mapping.get(p_type, "UNKNOWN")

        # Print program header details
        print(f"{p_type_name:<15} {hex(p_offset):<10} {hex(p_vaddr):<18} {hex(p_paddr):<18} {hex(p_filesz):<10} {hex(p_memsz):<10} {hex(p_flags):<8} {hex(p_align):<10}")
    
    # Read ELF Section
    # sh_offset = fields[5]   # e_shoff: Start of section headers
    # sh_entry_size = fields[10]  # e_shentsize: Size of each section header
    # sh_num = fields[11]         # e_shnum: Number of section headers
    # sh_str_index = fields[12]   # e_shstrndx: Section header string table index
    # sh_entry_format = "<IIQQQQQQ"

    # print(f"Section Headers (Offset: {sh_offset}, Entries: {sh_num}):")
    # print(f"{'Name Offset':<12} {'Type':<12} {'Address':<18} {'Offset':<10} {'Size':<10} {'Flags':<10} {'Align':<10}")
    # print("=" * 80)

    # # Đọc từng section header
    # f.seek(sh_offset)  # Di chuyển con trỏ file tới vị trí của section headers
    # for i in range(sh_num):
    #     # Đọc một section header
    #     sh_entry = f.read(sh_entry_size)
    #     if len(sh_entry) != sh_entry_size:
    #         raise ValueError(f"Failed to read full section header entry {i}")

    # # Giải nén section header
    # sh_fields = struct.unpack(sh_entry_format, sh_entry[:56])

    # # Trích xuất các trường
    # sh_name_offset = sh_fields[0]
    # sh_type = sh_fields[1]
    # sh_flags = sh_fields[2]
    # sh_addr = sh_fields[3]
    # sh_offset = sh_fields[4]
    # sh_size = sh_fields[5]
    # sh_link = sh_fields[6]
    # sh_info = sh_fields[7]

    # # Hiển thị thông tin
    # print(f"{sh_name_offset:<12} {sh_type:<12} {hex(sh_addr):<18} {hex(sh_offset):<10} {hex(sh_size):<10} {hex(sh_flags):<10} {hex(sh_link):<10}")
