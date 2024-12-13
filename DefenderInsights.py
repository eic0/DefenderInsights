import sys
import os
import zlib
import struct
import re

SIGNATURE_TYPE_THREAT_BEGIN = 92
SIGNATURE_TYPE_THREAT_END = 93

# A partial map of signature types to names (extend as needed)
signature_type_names = {
    1: "SIGNATURE_TYPE_RESERVED",
    2: "SIGNATURE_TYPE_VOLATILE_THREAT_INFO",
    3: "SIGNATURE_TYPE_VOLATILE_THREAT_ID",
    17: "SIGNATURE_TYPE_CKOLDREC",
    32: "SIGNATURE_TYPE_KVIR32",
    33: "SIGNATURE_TYPE_POLYVIR32",
    39: "SIGNATURE_TYPE_NSCRIPT_NORMAL",
    40: "SIGNATURE_TYPE_NSCRIPT_SP",
    41: "SIGNATURE_TYPE_NSCRIPT_BRUTE",
    44: "SIGNATURE_TYPE_NSCRIPT_CURE",
    48: "SIGNATURE_TYPE_TITANFLT",
    61: "SIGNATURE_TYPE_PEFILE_CURE",
    62: "SIGNATURE_TYPE_MAC_CURE",
    64: "SIGNATURE_TYPE_SIGTREE",
    65: "SIGNATURE_TYPE_SIGTREE_EXT",
    66: "SIGNATURE_TYPE_MACRO_PCODE",
    67: "SIGNATURE_TYPE_MACRO_SOURCE",
    68: "SIGNATURE_TYPE_BOOT",
    73: "SIGNATURE_TYPE_CLEANSCRIPT",
    74: "SIGNATURE_TYPE_TARGET_SCRIPT",
    80: "SIGNATURE_TYPE_CKSIMPLEREC",
    81: "SIGNATURE_TYPE_PATTMATCH",
    83: "SIGNATURE_TYPE_RPFROUTINE",
    85: "SIGNATURE_TYPE_NID",
    86: "SIGNATURE_TYPE_GENSFX",
    87: "SIGNATURE_TYPE_UNPLIB",
    88: "SIGNATURE_TYPE_DEFAULTS",
    91: "SIGNATURE_TYPE_DBVAR",
    92: "SIGNATURE_TYPE_THREAT_BEGIN",
    93: "SIGNATURE_TYPE_THREAT_END",
    94: "SIGNATURE_TYPE_FILENAME",
    95: "SIGNATURE_TYPE_FILEPATH",
    96: "SIGNATURE_TYPE_FOLDERNAME",
    97: "SIGNATURE_TYPE_PEHSTR",
    98: "SIGNATURE_TYPE_LOCALHASH",
    99: "SIGNATURE_TYPE_REGKEY",
    100: "SIGNATURE_TYPE_HOSTSENTRY",
    103: "SIGNATURE_TYPE_STATIC",
    105: "SIGNATURE_TYPE_LATENT_THREAT",
    106: "SIGNATURE_TYPE_REMOVAL_POLICY",
    107: "SIGNATURE_TYPE_WVT_EXCEPTION",
    108: "SIGNATURE_TYPE_REVOKED_CERTIFICATE",
    112: "SIGNATURE_TYPE_TRUSTED_PUBLISHER",
    113: "SIGNATURE_TYPE_ASEP_FILEPATH",
    115: "SIGNATURE_TYPE_DELTA_BLOB",
    116: "SIGNATURE_TYPE_DELTA_BLOB_RECINFO",
    117: "SIGNATURE_TYPE_ASEP_FOLDERNAME",
    119: "SIGNATURE_TYPE_PATTMATCH_V2",
    120: "SIGNATURE_TYPE_PEHSTR_EXT",
    121: "SIGNATURE_TYPE_VDLL_X86",
    122: "SIGNATURE_TYPE_VERSIONCHECK",
    123: "SIGNATURE_TYPE_SAMPLE_REQUEST",
    124: "SIGNATURE_TYPE_VDLL_X64",
    126: "SIGNATURE_TYPE_SNID",
    127: "SIGNATURE_TYPE_FOP",
    128: "SIGNATURE_TYPE_KCRCE",
    131: "SIGNATURE_TYPE_VFILE",
    132: "SIGNATURE_TYPE_SIGFLAGS",
    133: "SIGNATURE_TYPE_PEHSTR_EXT2",
    134: "SIGNATURE_TYPE_PEMAIN_LOCATOR",
    135: "SIGNATURE_TYPE_PESTATIC",
    136: "SIGNATURE_TYPE_UFSP_DISABLE",
    137: "SIGNATURE_TYPE_FOPEX",
    138: "SIGNATURE_TYPE_PEPCODE",
    139: "SIGNATURE_TYPE_IL_PATTERN",
    140: "SIGNATURE_TYPE_ELFHSTR_EXT",
    141: "SIGNATURE_TYPE_MACHOHSTR_EXT",
    142: "SIGNATURE_TYPE_DOSHSTR_EXT",
    143: "SIGNATURE_TYPE_MACROHSTR_EXT",
    144: "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE",
    145: "SIGNATURE_TYPE_VDLL_IA64",
    149: "SIGNATURE_TYPE_PEBMPAT",
    150: "SIGNATURE_TYPE_AAGGREGATOR",
    151: "SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME",
    152: "SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME",
    153: "SIGNATURE_TYPE_TUNNEL_X86",
    154: "SIGNATURE_TYPE_TUNNEL_X64",
    155: "SIGNATURE_TYPE_TUNNEL_IA64",
    156: "SIGNATURE_TYPE_VDLL_ARM",
    157: "SIGNATURE_TYPE_THREAD_X86",
    158: "SIGNATURE_TYPE_THREAD_X64",
    159: "SIGNATURE_TYPE_THREAD_IA64",
    160: "SIGNATURE_TYPE_FRIENDLYFILE_SHA256",
    161: "SIGNATURE_TYPE_FRIENDLYFILE_SHA512",
    162: "SIGNATURE_TYPE_SHARED_THREAT",
    163: "SIGNATURE_TYPE_VDM_METADATA",
    164: "SIGNATURE_TYPE_VSTORE",
    165: "SIGNATURE_TYPE_VDLL_SYMINFO",
    166: "SIGNATURE_TYPE_IL2_PATTERN",
    167: "SIGNATURE_TYPE_BM_STATIC",
    168: "SIGNATURE_TYPE_BM_INFO",
    169: "SIGNATURE_TYPE_NDAT",
    170: "SIGNATURE_TYPE_FASTPATH_DATA",
    171: "SIGNATURE_TYPE_FASTPATH_SDN",
    172: "SIGNATURE_TYPE_DATABASE_CERT",
    173: "SIGNATURE_TYPE_SOURCE_INFO",
    174: "SIGNATURE_TYPE_HIDDEN_FILE",
    175: "SIGNATURE_TYPE_COMMON_CODE",
    176: "SIGNATURE_TYPE_VREG",
    177: "SIGNATURE_TYPE_NISBLOB",
    178: "SIGNATURE_TYPE_VFILEEX",
    179: "SIGNATURE_TYPE_SIGTREE_BM",
    180: "SIGNATURE_TYPE_VBFOP",
    181: "SIGNATURE_TYPE_VDLL_META",
    182: "SIGNATURE_TYPE_TUNNEL_ARM",
    183: "SIGNATURE_TYPE_THREAD_ARM",
    184: "SIGNATURE_TYPE_PCODEVALIDATOR",
    186: "SIGNATURE_TYPE_MSILFOP",
    187: "SIGNATURE_TYPE_KPAT",
    188: "SIGNATURE_TYPE_KPATEX",
    189: "SIGNATURE_TYPE_LUASTANDALONE",
    190: "SIGNATURE_TYPE_DEXHSTR_EXT",
    191: "SIGNATURE_TYPE_JAVAHSTR_EXT",
    192: "SIGNATURE_TYPE_MAGICCODE",
    193: "SIGNATURE_TYPE_CLEANSTORE_RULE",
    194: "SIGNATURE_TYPE_VDLL_CHECKSUM",
    195: "SIGNATURE_TYPE_THREAT_UPDATE_STATUS",
    196: "SIGNATURE_TYPE_VDLL_MSIL",
    197: "SIGNATURE_TYPE_ARHSTR_EXT",
    198: "SIGNATURE_TYPE_MSILFOPEX",
    199: "SIGNATURE_TYPE_VBFOPEX",
    200: "SIGNATURE_TYPE_FOP64",
    201: "SIGNATURE_TYPE_FOPEX64",
    202: "SIGNATURE_TYPE_JSINIT",
    203: "SIGNATURE_TYPE_PESTATICEX",
    204: "SIGNATURE_TYPE_KCRCEX",
    205: "SIGNATURE_TYPE_FTRIE_POS",
    206: "SIGNATURE_TYPE_NID64",
    207: "SIGNATURE_TYPE_MACRO_PCODE64",
    208: "SIGNATURE_TYPE_BRUTE",
    209: "SIGNATURE_TYPE_SWFHSTR_EXT",
    210: "SIGNATURE_TYPE_REWSIGS",
    211: "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    212: "SIGNATURE_TYPE_INNOHSTR_EXT",
    213: "SIGNATURE_TYPE_ROOTCERTSTORE",
    214: "SIGNATURE_TYPE_EXPLICITRESOURCE",
    215: "SIGNATURE_TYPE_CMDHSTR_EXT",
    216: "SIGNATURE_TYPE_FASTPATH_TDN",
    217: "SIGNATURE_TYPE_EXPLICITRESOURCEHASH",
    218: "SIGNATURE_TYPE_FASTPATH_SDN_EX",
    219: "SIGNATURE_TYPE_BLOOM_FILTER",
    220: "SIGNATURE_TYPE_RESEARCH_TAG",
    222: "SIGNATURE_TYPE_ENVELOPE",
    223: "SIGNATURE_TYPE_REMOVAL_POLICY64",
    224: "SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME",
    225: "SIGNATURE_TYPE_VDLL_META_X64",
    226: "SIGNATURE_TYPE_VDLL_META_ARM",
    227: "SIGNATURE_TYPE_VDLL_META_MSIL",
    228: "SIGNATURE_TYPE_MDBHSTR_EXT",
    229: "SIGNATURE_TYPE_SNIDEX",
    230: "SIGNATURE_TYPE_SNIDEX2",
    231: "SIGNATURE_TYPE_AAGGREGATOREX",
    232: "SIGNATURE_TYPE_PUA_APPMAP",
    233: "SIGNATURE_TYPE_PROPERTY_BAG",
    234: "SIGNATURE_TYPE_DMGHSTR_EXT",
    235: "SIGNATURE_TYPE_DATABASE_CATALOG",
}

def extract_vdm(filename):
    """
    Extract and decompress the VDM file to create a .extracted file.
    """
    with open(filename, "rb") as f:
        data = f.read()

    # Locate RMDX resource
    try:
        base = data.index(b"RMDX")
    except ValueError:
        print(f"Skipping {filename}: No RMDX signature found.")
        return None

    offset, size = struct.unpack("II", data[base + 0x18: base + 0x20])

    # Decompress
    try:
        x = zlib.decompress(data[base + offset + 8:], -15)
    except zlib.error:
        print(f"Skipping {filename}: zlib decompression failed.")
        return None

    outname = filename + ".extracted"
    with open(outname, "wb") as out_f:
        out_f.write(x)
    return outname

def parse_tlv_stream(data):
    """
    Generator that yields (sig_type, value) tuples from TLV-formatted data.
    """
    pos = 0
    length = len(data)
    while pos < length:
        if pos + 4 > length:
            break
        sig_type = data[pos]
        size_low = data[pos+1]
        size_high = data[pos+2] | (data[pos+3] << 8)
        size = size_low | (size_high << 8)
        pos += 4

        if pos + size > length:
            break

        value = data[pos:pos+size]
        pos += size

        yield sig_type, value

def extract_readable_strings(byte_data):
    """
    Extract readable ASCII strings from a bytes sequence.
    """
    text = byte_data.decode('latin-1', errors='ignore')
    strings = re.findall(r'[\x20-\x7e]{3,}', text)
    return strings

def search_threat_in_file(extracted_file, threat_name):
    """
    Search for the given threat_name (bytes) in the extracted vdm file.
    Print out the threat block if found.
    """
    with open(extracted_file, "rb") as f:
        data = f.read()

    in_threat_block = False
    current_block = []

    found_any = False

    for sig_type, value in parse_tlv_stream(data):
        if sig_type == SIGNATURE_TYPE_THREAT_BEGIN:
            # Start a new threat block
            in_threat_block = True
            current_block = [(sig_type, value)]
        elif sig_type == SIGNATURE_TYPE_THREAT_END and in_threat_block:
            # End of the threat block
            current_block.append((sig_type, value))

            # Check if this block contains our target threat name
            full_block_data = b"".join(val for _, val in current_block)
            if threat_name in full_block_data:
                found_any = True
                print(f"\nFound threat block for: {threat_name.decode(errors='replace')} in {extracted_file}")
                # Print the block contents
                for ttype, tvalue in current_block:
                    ttype_name = signature_type_names.get(ttype, f"UNKNOWN_TYPE_{ttype}")
                    if ttype == SIGNATURE_TYPE_THREAT_BEGIN:
                        print("[Threat Begin]")
                    elif ttype == SIGNATURE_TYPE_THREAT_END:
                        print("[Threat End]")
                    
                    print(f"Signature Type: {ttype} ({ttype_name})")
                    
                    print(f"Value (hex): {tvalue.hex()}")
                    # Attempt to extract readable strings
                    extracted_strings = extract_readable_strings(tvalue)
                    if extracted_strings:
                        print("Extracted text strings (possible function names/patterns):")
                        for s in extracted_strings:
                            print("  ", s)
                    else:
                        pass
            
            # Reset the block
            in_threat_block = False
            current_block = []
        else:
            # Continue accumulating signatures in the current threat block
            if in_threat_block:
                current_block.append((sig_type, value))

    return found_any

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 DefenderInsights.py <threat_name>")
        sys.exit(1)

    threat_name_input = sys.argv[1]
    target_threat_name = threat_name_input.encode('latin-1', errors='replace')

    vdms_dir = "vdms"
    if not os.path.isdir(vdms_dir):
        print(f"'{vdms_dir}' directory not found. Creating it...")
        os.makedirs(vdms_dir, exist_ok=True)
        print("Please provide vdm files from: 'C:\ProgramData\Microsoft\Windows Defender\Definition Updates\<GUID>\'")
        sys.exit(1)

    # Look for extracted files first
    extracted_files = [os.path.join(vdms_dir, f) for f in os.listdir(vdms_dir) if f.endswith(".vdm.extracted")]

    if not extracted_files:
        # If no extracted files, look for vdm files and extract them
        vdm_files = [os.path.join(vdms_dir, f) for f in os.listdir(vdms_dir) if f.endswith(".vdm")]
        if not vdm_files:
            print("No .vdm or .vdm.extracted files found in 'vdms' directory.")
            sys.exit(1)

        # Extract all vdm files
        extracted_files = []
        for vdmfile in vdm_files:
            outname = extract_vdm(vdmfile)
            if outname:
                extracted_files.append(outname)

        if not extracted_files:
            print("No .vdm files could be extracted.")
            sys.exit(1)

    # Search for the threatname in each extracted file
    found_any = False
    for ext_file in extracted_files:
        if search_threat_in_file(ext_file, target_threat_name):
            found_any = True
        else:
            print(f"Nothing found in '{ext_file}'.")
            

    if not found_any:
        print(f"No blocks found for threat '{threat_name_input}' in the available .vdm.extracted files.")

if __name__ == "__main__":
    main()
