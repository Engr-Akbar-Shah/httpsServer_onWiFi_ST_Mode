import subprocess
import sys
import re
import os
import csv

# Configuration
partition_size = 0x4000  # 16KB
namespace = "storage"
baud = "115200"
certs_dir = os.path.join("components", "certificates", "generated")

def ensure_certs_dir():
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)
        print(f"[✓] Created directory: {certs_dir}")

def get_mac_address(port):
    try:
        result = subprocess.run(
            ["esptool.py", "--port", port, "--baud", baud, "read_mac"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        mac_match = re.search(r"MAC:\s*([0-9A-Fa-f:]+)", result.stdout)
        if mac_match:
            raw_mac = mac_match.group(1)
            formatted = raw_mac.replace(":", "").upper()
            print("[✓] MAC:", raw_mac, "→", formatted)
            return formatted
        else:
            raise ValueError("MAC not found.")
    except Exception as e:
        print("[✗] MAC read failed:", e)
        sys.exit(1)

def generate_openssl_cert(mac):
    cert_file = os.path.join(certs_dir, f"serverCert_{mac}.pem")
    key_file = os.path.join(certs_dir, f"privateKey_{mac}.pem")
    subj = f"/CN=ESP32-{mac}"
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_file, "-x509", "-days", "3650",
        "-out", cert_file, "-subj", subj
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # <== suppress output
    return cert_file, key_file

def read_cert_file(filename):
    with open(filename, 'r') as f:
        return f.read()  # Return raw PEM content

def create_nvs_csv(mac, cert_str, key_str):
    csv_path = os.path.join(certs_dir, f"nvs_{mac}.csv")
    with open(csv_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["key", "type", "encoding", "value"])
        writer.writerow([namespace, "namespace", "", ""])
        writer.writerow(["serverCert", "data", "string", cert_str])
        writer.writerow(["privateKey", "data", "string", key_str])
        writer.writerow(["serverCertSize", "data", "u32", len(cert_str)])
        writer.writerow(["privateKeySize", "data", "u32", len(key_str)])
    print(f"[✓] Created CSV: {csv_path}")
    return csv_path

def create_nvs_bin(csv_path, mac):
    bin_path = os.path.join(certs_dir, f"nvs_{mac}.bin")
    subprocess.run([
        "python", os.path.join(os.environ["IDF_PATH"], "components", "nvs_flash", "nvs_partition_generator", "nvs_partition_gen.py"),
        "generate", csv_path, bin_path, str(partition_size)
    ], check=True)
    print(f"[✓] Created BIN: {bin_path}")
    return bin_path

def flash_nvs(port, chip, offset, bin_path):
    subprocess.run([
        "esptool.py", "--chip", chip, "--port", port, "--baud", baud,
        "write_flash", offset, bin_path
    ], check=True)
    print(f"[✓] Flashed to offset {offset}")

def main():
    if len(sys.argv) < 4:
        print("Usage: python gen_and_flash_certs.py <OFFSET> <CHIP> <PORT>")
        print("Example: python gen_and_flash_certs.py 0xF000 esp32s3 /dev/ttyUSB0")
        sys.exit(1)

    offset = sys.argv[1]
    chip = sys.argv[2]
    port = sys.argv[3]

    ensure_certs_dir()
    mac = get_mac_address(port)
    cert_path, key_path = generate_openssl_cert(mac)
    cert_str = read_cert_file(cert_path)
    key_str = read_cert_file(key_path)
    csv_path = create_nvs_csv(mac, cert_str, key_str)
    bin_path = create_nvs_bin(csv_path, mac)
    flash_nvs(port, chip, offset, bin_path)

if __name__ == "__main__":
    main()
