import asyncio
import json
import logging
import frida
from aiohttp import web

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nuna_ai_bridge")

# Global state
LATEST_HEART_RATE = {"hr": None, "timestamp": None}

def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if isinstance(payload, dict) and payload.get("type") == "heart_rate":
            LATEST_HEART_RATE["hr"] = payload["hr"]
            LATEST_HEART_RATE["timestamp"] = payload["timestamp"]
            logger.info(f"Received HR from Android: {payload['hr']} bpm at {payload['timestamp']}")
        else:
            logger.info(f"Frida send payload: {payload}")
    elif message["type"] == "log":
        logger.info(f"Frida console: {message.get('payload')}")
    else:
        logger.info(f"Message from frida: {message}")

async def start_frida():
    logger.info("Connecting to Frida Gadget...")
    try:
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        session = device.attach("Gadget")
        logger.info("Attached to Gadget!")
        
        with open("compiled_bridge.js") as f:
            script = session.create_script(f.read())
        script.on("message", on_message)
        script.load()
        try:
            device.resume(session._impl.pid)
            logger.info("Resumed Gadget!")
        except Exception as e:
            logger.info(f"Could not resume Gadget: {e}")
        return script
    except Exception as e:
        logger.error(f"Failed to attach to frida gadget: {e}")
        return None

async def handle_process(request):
    try:
        data = await request.json()
        if script:
            script.exports_sync.process_heart_rate(json.dumps(data))
            return web.json_response({"status": "ok"})
        else:
            return web.json_response({"status": "error", "message": "Frida not connected"}, status=500)
    except Exception as e:
        logger.error(f"Error in handle_process: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500, headers={"Access-Control-Allow-Origin": "*"})

async def handle_hr(request):
    return web.json_response(LATEST_HEART_RATE, headers={"Access-Control-Allow-Origin": "*"})

script = None

async def main():
    global script
    script = await start_frida()
    
    app = web.Application()
    app.router.add_post('/process', handle_process)
    app.router.add_get('/hr', handle_hr)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()
    logger.info("HTTP Server listening on http://localhost:8080")
    
    # Keep running
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
