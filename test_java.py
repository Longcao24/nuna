import frida
import time

def on_message(msg, data):
    print(msg)

device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
session = device.attach("Gadget")
script = session.create_script("""
    if (Java.available) {
        Java.perform(function () {
            send({type: 'res', payload: 'Java is available!'});
        });
    } else {
        send({type: 'res', payload: 'Java is NOT available'});
    }
""")
script.on("message", on_message)
script.load()
device.resume(session._impl.pid)
time.sleep(2)
