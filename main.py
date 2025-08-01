# =================================================================
# MetaGuard v1.1 - API-Ready Forensics Engine
# =================================================================

import os
import argparse
import string
import hashlib
import re
import zipfile
from dotenv import load_dotenv

# --- Library Imports ---
import magic
import piexif
import requests
from PIL import Image
import exifread
from PyPDF2 import PdfReader, PdfWriter

# --- Configuration ---
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ===============================================================
# SECTION 1: CORE EXTRACTION FUNCTIONS
# ===============================================================

def extract_image_metadata(file_path):
    metadata = {}
    try:
        with Image.open(file_path) as img:
            metadata['Format'] = img.format; metadata['Size'] = img.size; metadata['Mode'] = img.mode
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            if tags:
                for tag, value in tags.items():
                    if tag not in ('JPEGThumbnail', 'TIFFThumbnail'): metadata[str(tag)] = str(value)
        return metadata
    except Exception as e: return {"error": str(e)}

def extract_pdf_metadata(file_path):
    try:
        with open(file_path, 'rb') as f:
            reader = PdfReader(f)
            info = reader.metadata
            return info if info else {}
    except Exception as e: return {"error": str(e)}


# ===============================================================
# SECTION 2: ANALYSIS & THREAT DETECTION FUNCTIONS
# ===============================================================

def analyze_metadata_risks(metadata_dict, file_type):
    if not metadata_dict or "error" in metadata_dict: return []
    warnings = []
    if file_type == 'image':
        if any('GPS' in key for key in metadata_dict): warnings.append("High Privacy Risk: Image contains GPS location data.")
        if 'Image Make' in metadata_dict or 'Image Model' in metadata_dict: warnings.append(f"Informational: Image contains device info (Make: {metadata_dict.get('Image Make')}, Model: {metadata_dict.get('Image Model')}).")
    elif file_type == 'pdf':
        if metadata_dict.get('/Author'): warnings.append(f"Informational: PDF contains Author name: {metadata_dict.get('/Author')}.")
        if metadata_dict.get('/Creator'): warnings.append(f"Informational: PDF reveals creator software: {metadata_dict.get('/Creator')}.")
    return warnings

def get_true_file_type(file_path):
    try:
        mime_type = magic.from_file(file_path, mime=True)
        reported_ext = os.path.splitext(file_path)[1].lower()
        is_mismatch = (reported_ext == '.jpg' and 'jpeg' not in mime_type) or \
                      (reported_ext == '.pdf' and 'pdf' not in mime_type)
        return {
            "reported_ext": reported_ext,
            "mime_type": mime_type,
            "is_mismatch": is_mismatch
        }
    except Exception as e:
        return {"error": str(e)}

def detect_lsb_steganography(file_path):
    try:
        with Image.open(file_path) as img:
            if img.mode not in ['RGB', 'RGBA']: return "Analysis skipped: LSB check only supports RGB/RGBA images."
            pixels = img.load(); width, height = img.size; binary_message = ""
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y][:3]
                    binary_message += str(r & 1) + str(g & 1) + str(b & 1)
            message_bytes = bytearray(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8) if len(binary_message[i:i+8])==8)
            potential_message = message_bytes.decode('ascii', errors='ignore')
            printable_chars = set(string.printable)
            longest_run = max(len(run) for run in ''.join(c if c in printable_chars else ' ' for c in potential_message).split()) if potential_message else 0
            if longest_run > 10:
                return f"High Possibility of Steganography Detected! Found a run of {longest_run} printable characters."
            else:
                return "No obvious signs of LSB steganography detected."
    except Exception as e:
        return f"Error during steganography analysis: {e}"

def check_for_macros(file_path):
    if not file_path.endswith(('.docx', '.docm', '.pptx', '.pptm', '.xlsx', '.xlsm')): return None
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            if 'word/vbaProject.bin' in zf.namelist() or 'ppt/vbaProject.bin' in zf.namelist() or 'xl/vbaProject.bin' in zf.namelist():
                return "High Security Risk: Document contains macros, which can execute malicious code."
            else:
                return "No macros detected."
    except zipfile.BadZipFile:
        return "Not a standard zip-based office document."

def find_urls_in_pdf(file_path):

    if not file_path.endswith('.pdf'): return []
    try:
        with open(file_path, 'rb') as f:
            reader = PdfReader(f)
            urls_found = []
            for page in reader.pages:
                text = page.extract_text()
                if text: urls_found.extend(re.findall(r'https?://\S+', text))
        return urls_found
    except Exception:
        return []

def check_virustotal(file_path):
    
    if not VT_API_KEY: return {"error": "VirusTotal API key not found in .env file."}
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_vendors = sum(stats.values())
            return {
                "hash": file_hash, "malicious": malicious, "suspicious": suspicious,
                "total_vendors": total_vendors, "status": "found"
            }
        elif response.status_code == 404: return {"hash": file_hash, "status": "not_found"}
        else: return {"error": f"API error {response.status_code}", "hash": file_hash}
    except requests.RequestException as e: return {"error": f"Connection error: {e}", "hash": file_hash}

# ===============================================================
# SECTION 3: CLEANING & DESTRUCTION FUNCTIONS
# ===============================================================


def clean_image_metadata(source_path, output_path):
    try:
        piexif.remove(source_path, output_path)
        return True
    except Exception: return False

def clean_pdf_metadata(source_path, output_path):
    try:
        with open(source_path, 'rb') as f_in:
            reader = PdfReader(f_in); writer = PdfWriter()
            for page in reader.pages: writer.add_page(page)
            with open(output_path, 'wb') as f_out: writer.write(f_out)
        return True
    except Exception: return False

def destroy_steganography(source_path, output_path):
    try:
        with Image.open(source_path) as img:
            if img.mode == 'RGBA': img = img.convert('RGB')
            img.save(output_path, quality=95)
        return True
    except Exception: return False


# ===============================================================
# SECTION 4: MAIN EXECUTION LOGIC (CLI Presentation Layer)
# ===============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MetaGuard v1.1: An all-in-one file forensics and cleaning tool.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("file", help="Path to the file to be processed.")
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("-a", "--analyze", action="store_true", help="Run a full suite of local analyses (default action).")
    action_group.add_argument("-c", "--clean", nargs='?', const="cleaned", default=None, help="Clean metadata. Optionally specify suffix.")
    action_group.add_argument("-d", "--destroy-steg", nargs='?', const="steg_destroyed", default=None, help="Destroy LSB steganography in an image.")
    parser.add_argument("-vt", "--vt-check", action="store_true", help="Perform a VirusTotal check (requires API key).")
    
    args = parser.parse_args()
    file_path = args.file

    if not os.path.exists(file_path):
        print(f"Error: File not found at '{file_path}'")
    else:
        base, ext = os.path.splitext(file_path)
        ext = ext.lower()

        # --- CLI Action Dispatcher ---
        if args.clean is not None:
            output_filename = f"{base}_{args.clean}{ext}"
            success = False
            if ext in ['.jpg', '.jpeg', '.png', '.tiff']: success = clean_image_metadata(file_path, output_filename)
            elif ext == '.pdf': success = clean_pdf_metadata(file_path, output_filename)
            else: print(f"Cleaning not supported for file type '{ext}'.")
            if success: print(f"\n[SUCCESS] Cleaned file saved to: {output_filename}")
            else: print(f"\n[ERROR] Could not clean file.")
        
        elif args.destroy_steg is not None:
            output_filename = f"{base}_{args.destroy_steg}{ext}"
            if ext in ['.jpg', '.jpeg', '.png', '.tiff']:
                if destroy_steganography(file_path, output_filename):
                    print(f"\n[SUCCESS] Steganography potentially destroyed. New file saved to: {output_filename}")
                else: print("\n[ERROR] Could not process image to destroy steganography.")
            else: print("Steganography destruction only supported for image files.")

        else: # Default action is to analyze
            print(f"--- Starting Full Analysis for: {os.path.basename(file_path)} ---")
            
            # True file type
            type_info = get_true_file_type(file_path)
            print("\n--- True File Type Analysis ---")
            if "error" in type_info: print(f"[ERROR] {type_info['error']}")
            else:
                print(f"Reported Extension: {type_info['reported_ext']}")
                print(f"True Content Type (MIME): {type_info['mime_type']}")
                if type_info['is_mismatch']: print("[!!!] CRITICAL MISMATCH: File extension does not match its true content!")
            
            # Metadata and risks
            metadata = {}
            if ext in ['.jpg', '.jpeg', '.png', '.tiff']: metadata = extract_image_metadata(file_path)
            elif ext == '.pdf': metadata = extract_pdf_metadata(file_path)
            
            if metadata and "error" not in metadata:
                print("\n--- Metadata ---")
                for k, v in metadata.items(): print(f"{k}: {v}")
                
                risks = analyze_metadata_risks(metadata, 'image' if ext in ['.jpg', '.jpeg'] else 'pdf')
                if risks:
                    print("\n--- Metadata Risk Report ---")
                    for risk in risks: print(f"[!] {risk}")
            
            # Advanced analysis
            print("\n--- Advanced Local Analysis ---")
            print(f"Steganography: {detect_lsb_steganography(file_path)}")
            macro_result = check_for_macros(file_path)
            if macro_result: print(f"Macros: {macro_result}")
            pdf_urls = find_urls_in_pdf(file_path)
            if pdf_urls: print(f"Embedded URLs: Found {len(pdf_urls)}. First URL: {pdf_urls[0]}")
            
            # VirusTotal check
            if args.vt_check:
                print("\n--- VirusTotal Cloud Analysis ---")
                vt_result = check_virustotal(file_path)
                if "error" in vt_result: print(f"[ERROR] {vt_result['error']}")
                elif vt_result['status'] == 'not_found': print(f"[INFO] File hash not found on VirusTotal.")
                elif vt_result['status'] == 'found':
                    if vt_result['malicious'] > 0: print(f"[!!!] CRITICAL RISK: VirusTotal reports this file is MALICIOUS ({vt_result['malicious']}/{vt_result['total_vendors']} vendors).")
                    elif vt_result['suspicious'] > 0: print(f"[!] High Risk: VirusTotal reports this file as SUSPICIOUS ({vt_result['suspicious']} vendors).")
                    else: print("[SUCCESS] VirusTotal reports this file is clean.")
