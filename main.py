
from multiprocessing import Process
import asyncio
import os
import time

def run_peer(node_id):
    import asyncio
    import os
    os.environ["PORT_OFFSET"] = str(node_id)
    from node import start_node

    async def main():
        await start_node(node_id=node_id, developer_mode=True)
        while True:
            await asyncio.sleep(3600)

    asyncio.run(main())

if __name__ == "__main__":
    for i in range(4):
        Process(target=run_peer, args=(i,)).start()
    while True:
        time.sleep(1)