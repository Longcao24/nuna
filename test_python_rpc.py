import frida
import time
import json

def on_message(msg, data):
    print(msg)

device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
session = device.attach("Gadget")
with open("compiled.js") as f:
    script = session.create_script(f.read())
script.on("message", on_message)
script.load()

print("Script loaded")
time.sleep(1)
try:
    print("Calling testFunction...")
    script.exports_sync.test_function({"hello": "world"})
    print("Call successful")
except Exception as e:
    print("Error calling exports: ", e)

time.sleep(1)
