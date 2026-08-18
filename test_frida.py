import frida
import sys

def main():
    try:
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        print("[*] Resuming Gadget...")
        device.resume(28142)
        device.resume("Gadget")
        print("[*] Resumed!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
