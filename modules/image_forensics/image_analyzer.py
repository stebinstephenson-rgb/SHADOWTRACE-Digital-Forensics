import hashlib
import subprocess
import json

def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file to verify integrity."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_exif(filepath):
    """Uses ExifTool to extract image metadata."""
    try:
        result = subprocess.run(
            ["exiftool", "-json", "-G", filepath],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        if data:
            return data[0]
        return {"Error": "No metadata found"}
    except subprocess.CalledProcessError as e:
        return {"Error": f"ExifTool failed: {e.stderr}"}
    except FileNotFoundError:
        return {"Error": "ExifTool is not installed or not in PATH."}

def analyze_image(filepath):
    """Runs all image forensics checks."""
    file_hash = calculate_sha256(filepath)
    metadata = extract_exif(filepath)
    
    return {
        "sha256": file_hash,
        "metadata": metadata
    }