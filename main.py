import asyncio
from threading import Thread
from node import start_node

blockchain_community = None

def boot_node():
    global blockchain_community
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    blockchain_community = loop.run_until_complete(start_node(node_id=0, developer_mode=True))
    loop.run_forever()

# Optional: expose blockchain_community to be imported
__all__ = ["blockchain_community"]

if __name__ == "__main__":
    # Start node in background thread
    Thread(target=boot_node, daemon=True).start()