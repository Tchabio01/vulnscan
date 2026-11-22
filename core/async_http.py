import asyncio
try:
    import aiohttp
except ImportError:
    aiohttp = None


async def fetch_all(urls, timeout=10, concurrency=20):
    if aiohttp is None:
        print("[!] aiohttp non installe")
        return []
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
        async def one(u):
            async with sem:
                try:
                    async with s.get(u, ssl=False) as r:
                        return u, r.status, await r.text()
                except Exception:
                    return u, None, ""
        return await asyncio.gather(*(one(u) for u in urls))


def fetch_all_sync(urls, **kw):
    return asyncio.run(fetch_all(urls, **kw))
