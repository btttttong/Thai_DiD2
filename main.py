import asyncio
from threading import Thread
from node import start_node
import time

communities = []

def boot_node(node_id):
    async def runner():
        community = await start_node(node_id=node_id, developer_mode=True)
        communities.append(community)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(runner())
    loop.run_forever()

if __name__ == "__main__":
    print("🟢 Starting 3 nodes...")
    for i in range(3):
        Thread(target=boot_node, args=(i,), daemon=True).start()

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("🛑 Exiting.")