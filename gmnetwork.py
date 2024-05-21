import asyncio
import sys
import random
import string
import time
from curl_cffi.requests import AsyncSession
from eth_account.messages import encode_defunct
from web3 import AsyncWeb3
from loguru import logger
import re

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")

nstProxyAppId = "7DC02E313D744F26"


def add_nstproxy_appid(proxy):
    if "nstproxy." in proxy:
        pattern = r"^(?:[^:]+)://([^:]+):[^@]+@"
        match = re.match(pattern, proxy)
        if match:
            username = match.group(1)
            if "appId" not in username:
                newusername = "{}-appid_{}".format(username, nstProxyAppId)
                proxy = proxy.replace(username, newusername)
                return proxy
    return proxy


class CaptchaSolver:
    def __init__(self, api_key):
        self.session = AsyncSession(timeout=120, impersonate="chrome120")
        self.api_key = api_key
        self.task_id = None

    async def create_task(self):
        payload = {
            "clientKey": self.api_key,
            "appId": "69AE5D43-F131-433D-92C8-0947B2CF150A",
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": 'https://launchpad.gmnetwork.ai',
                "websiteKey": '0x4AAAAAAAaAdLjFNjUZZwWZ'
            }
        }
        for attempt in range(3):
            try:
                response = await self.session.post('https://api.capsolver.com/createTask', json=payload)
                response_data = response.json()
                if response_data['errorId'] == 0:
                    self.task_id = response_data['taskId']
                    return True
            except Exception as e:
                logger.error(f"create_task attempt {attempt + 1} failed: {e}")
        return False

    async def solve(self):
        if not await self.create_task():
            return None

        payload = {
            "clientKey": self.api_key,
            "taskId": self.task_id
        }
        for attempt in range(30):
            try:
                response = await self.session.post('https://api.capsolver.com/getTaskResult', json=payload)
                response_data = response.json()
                if response_data['errorId'] == 0 and response_data['status'] == 'ready':
                    return response_data['solution']['token']
                elif response_data['errorId'] == 1:
                    return None
            except Exception as e:
                logger.error(f"solve attempt {attempt + 1} failed: {e}")
            await asyncio.sleep(3)
        return None


class GMNetworkClient:
    def __init__(self, proxy_channel, proxy_password, private_key, captcha_key):
        self.web3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://klaytn.api.onfinality.io/public'))
        self.session = AsyncSession(timeout=120, impersonate="chrome120")
        self.captcha_solver = CaptchaSolver(captcha_key)
        self.proxy_channel = proxy_channel
        self.proxy_password = proxy_password
        self.account = self.web3.eth.account.from_key(private_key)
        self.star_level = 0

    async def authenticate(self, initial_state=False):
        try:
            captcha_token = await self.captcha_solver.solve()
            if captcha_token is None:
                return False

            session_id = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
            proxy_url = add_nstproxy_appid(
                f"http://{self.proxy_channel}-residential-country_ANY-r_5m-s_{session_id}:{self.proxy_password}@gw-us.nstproxy.io:24125")
            self.session = AsyncSession(timeout=120, impersonate="chrome120", proxy=proxy_url)

            timestamp = int(time.time())
            sign_message = f"Welcome to GM Launchpad.\nPlease sign this message to login GM Launchpad.\n\nTimestamp: {timestamp}"
            signature = self.account.sign_message(encode_defunct(text=sign_message))

            login_payload = {
                "address": self.account.address,
                "message": "Welcome to GM Launchpad.\nPlease sign this message to login GM Launchpad.",
                "timestamp": timestamp,
                "signature": signature['signature'].hex()[2:],
                "login_type": 100
            }
            headers = {'Cf-Turnstile-Resp': captcha_token}

            response = await self.session.post("https://api-launchpad.gmnetwork.ai/user/login/", json=login_payload,
                                               headers=headers)
            response_data = response.json()

            if response_data['success']:
                access_token = response_data['result']['access_token']
                invite_code = response_data['result']['user_info']['invite_code']
                status = response_data['result']['user_info']['status']
                self.session.headers.update({"Access-Token": access_token})
                if initial_state:
                    return True
                logger.success(f"[{self.account.address}] Login successful.")
                if status == 300:
                    await self.bind_invite_code()
                elif status == 100 and "token_id" not in response_data['result']['user_info']['agent']:
                    await self.set_agent()
                else:
                    return await self.check_tasks()
            else:
                logger.error(f"[{self.account.address}] Login failed")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] Login failed: {e}")
            return False

    async def bind_invite_code(self):
        try:
            payload = {"invite_code": "GMGN", "address": self.account.address}
            response = await self.session.post("https://api-launchpad.gmnetwork.ai/user/invite_code/", json=payload)
            response_data = response.json()

            if response_data['success']:
                logger.success(f"[{self.account.address}] Successfully bind code")
                return await self.set_agent()
            else:
                logger.error(f"[{self.account.address}] Failed bind code")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] Failed bind code: {e}")
            return False

    async def set_agent(self):
        try:
            payload = {"nft_id": ""}
            response = await self.session.post("https://api-launchpad.gmnetwork.ai/user/auth/agent_set/", json=payload)
            response_data = response.json()

            if response_data['success']:
                if "token_id" in response_data['result']:
                    logger.success(f"[{self.account.address}] Proxy set successfully")
                    return await self.check_tasks()
                else:
                    return await self.set_agent()
            else:
                logger.error(f"[{self.account.address}] Proxy set failed")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] Proxy set failed: {e}")
            return False

    async def check_tasks(self):
        try:
            response = await self.session.get("https://api-launchpad.gmnetwork.ai/task/auth/task_center/?season_um=1")
            response_data = response.json()

            if response_data['success']:
                check_in_task_info = response_data['result']['check_in_task_info']
                last_check_in_time = check_in_task_info['last_check_in_time']
                check_in_task_info['title'] = "CHECK-IN"
                if int(time.time()) - last_check_in_time > 86400:
                    check_in_task_info['task_done_time'] = 0
                else:
                    check_in_task_info['task_done_time'] = 1
                task_list = [check_in_task_info]
                task_list += response_data['result']['launchpad_tasks_info']

                for index, task in enumerate(task_list):
                    task_id = task['id']
                    task_done_time = task['task_done_time']
                    title = task['title']
                    if task_done_time == 0:
                        await self.complete_task(task_id, title)
                        if index % 4 == 0 and index != 0 and index != len(task_list) - 1:
                            logger.info(f"[{self.account.address}] sleep 30s")
                            await asyncio.sleep(30)
                await self.get_user_energy()
                return True
            else:
                logger.error(f"[{self.account.address}] Get Task Failed.")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] Get Task Failed: {e}")
            return False

    async def complete_task(self, task_id, title, category=100):
        try:
            payload = {"category": category, "task_id": task_id}
            response = await self.session.post("https://api-launchpad.gmnetwork.ai/task/auth/task/", json=payload)

            if response.status_code == 200 and response.json()['success']:
                logger.success(
                    f"[{self.account.address}] {'Receive' if category == 100 else 'CLAIM'} Task {title} successfully")
                if category == 100:
                    return await self.complete_task(task_id, title, 200)
                else:
                    return True
            else:
                logger.error(
                    f"[{self.account.address}] {'Receive' if category == 100 else 'CLAIM'} Task {title} failed")
                return False
        except Exception as e:
            logger.error(
                f"[{self.account.address}] {'Receive' if category == 100 else 'CLAIM'} Task {title} failed: {e}")
            return False

    async def get_user_energy(self):
        try:
            response = await self.session.get("https://api-launchpad.gmnetwork.ai/energy/auth/user_energy/")
            response_data = response.json()

            if response_data['success']:
                logger.success(f"[{self.account.address}] MY GN：{response_data['result']['total']}")
                return True
            else:
                logger.error(f"[{self.account.address}] Get GN Failed")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] Get GN Failed: {e}")
            return False


async def process_account(semaphore, proxy_channel, proxy_password, private_key, captcha_key):
    async with semaphore:
        for attempt in range(3):
            if await GMNetworkClient(proxy_channel, proxy_password, private_key, captcha_key).authenticate():
                break


async def execute(private_key_list, max_concurrent_tasks, nstproxyChannel, proxy_password, captcha_key):
    semaphore = asyncio.Semaphore(max_concurrent_tasks)
    async with semaphore:
        tasks = [process_account(semaphore, nstproxyChannel, proxy_password, private_key, captcha_key) for private_key
                 in private_key_list]
        await asyncio.gather(*tasks)


if __name__ == '__main__':
    nst_proxy_channel = ""
    nst_proxy_password = ""
    capsolver_key = ""
    max_concurrent_tasks = 5

    # Your wallet private key
    private_key_list = [
        "",
        ""
    ]

    asyncio.run(execute(private_key_list, max_concurrent_tasks, nst_proxy_channel, nst_proxy_password,
                        capsolver_key))
