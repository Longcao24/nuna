import subprocess
import time
import json

p = subprocess.Popen(
    [".venv/bin/frida", "-H", "127.0.0.1:27042", "Gadget", "-q", "-l", "hook.js"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

time.sleep(2)
print("Sending command...")
p.stdin.write('rpc.exports.testFunction({"hello": "world"});\n')
p.stdin.flush()

time.sleep(1)
p.kill()
