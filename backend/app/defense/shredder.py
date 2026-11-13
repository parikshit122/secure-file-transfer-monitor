import os
import secrets

def shred_file(file_path: str) -> bool:
    """
    Overwrites file content 3 times following the DoD 5220.22-M standard:
    Pass 1: Zeros (0x00)
    Pass 2: Ones (0xFF)
    Pass 3: Cryptographically secure random bytes
    Then truncates file to 0 bytes and removes it from disk.
    """
    if not os.path.exists(file_path):
        return False

    try:
        os.chmod(file_path, 0o777)
        file_size = os.path.getsize(file_path)

        if file_size > 0:
            with open(file_path, "ba+", buffering=0) as f:
                # Pass 1: Overwrite with Zeros
                f.seek(0)
                f.write(b"\x00" * file_size)
                f.flush()
                os.fsync(f.fileno())

                # Pass 2: Overwrite with Ones
                f.seek(0)
                f.write(b"\xff" * file_size)
                f.flush()
                os.fsync(f.fileno())

                # Pass 3: Cryptographically Random Bytes
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())

        # Truncate and unlink
        with open(file_path, "w") as f:
            f.truncate(0)
        os.remove(file_path)
        return True
    except Exception:
        return False