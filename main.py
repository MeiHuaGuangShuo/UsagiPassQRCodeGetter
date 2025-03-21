import base64
import uiautomation as auto
from datetime import datetime, timedelta
from PIL import ImageGrab, ImageEnhance
from pyzbar.pyzbar import decode
import time
from urllib.parse import quote_plus
from aiohttp import web
from aiohttp.web_exceptions import HTTPUnauthorized
from aiohttp.web_request import BaseRequest
import asyncio
import hashlib


entryPoint = "/login"  # 登录页面入口，建议修改以防非法登录
loginUserName = "admin"  # 登录用户名
loginPassword = "maimaidx"  # 登录密码
port = 8080  # 监听端口
dxpass_url = "https://up.turou.fun/"  # 用于显示DXPass的URL


with open("main.html", "r", encoding="utf-8") as f:
    html = f.read()
with open("forbidden.html", "r", encoding="utf-8") as f:
    forbiddenHtml = f.read()


def generate_cookie_value(username, password):
    return hashlib.sha256(f"{username}:{password}".encode()).hexdigest()


async def auth_middleware(app, handler):
    async def middleware_handler(request):
        if request.path == entryPoint:
            return await handler(request)
        
        cookie_value = request.cookies.get('auth_cookie')
        expected = generate_cookie_value(loginUserName, loginPassword)
        
        if cookie_value != expected:
            response = web.Response(status=403, text=forbiddenHtml, content_type='text/html')
            response.del_cookie('auth_cookie')
            response.headers['WWW-Authenticate'] = 'Basic realm="Logged Out"'
            return response
        
        return await handler(request)
    return middleware_handler


async def login_handler(request):
    auth_header = request.headers.get('Authorization')
    
    if auth_header and auth_header.startswith('Basic '):
        try:
            encoded = auth_header.split()[1]
            decoded = base64.b64decode(encoded).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            if username == loginUserName and password == loginPassword:
                cookie_value = generate_cookie_value(username, password)
                response = web.HTTPTemporaryRedirect("/")
                response.set_cookie('auth_cookie', cookie_value, httponly=True)
                return response
        except:
            pass
    
    response = web.Response(
        status=401,
        text="Authentication Required",
        headers={'WWW-Authenticate': 'Basic realm="Secure Area"'}
    )
    return response


async def logout_handler(request):
    response = web.HTTPTemporaryRedirect("/")
    response.del_cookie('auth_cookie')
    response.headers['WWW-Authenticate'] = 'Basic realm="Logged Out"'
    return response


def is_valid_qrcode(image):
    gray = image.convert('L')
    decoded = decode(gray)
    return len(decoded) > 0


def main():
    handleTime = time.time()
    maimaiWindow = auto.WindowControl(searchDepth=1, Name="舞萌丨中二", ClassName='ChatWnd')
    nowFocusWindow = auto.GetForegroundControl()
    btn = maimaiWindow.ButtonControl(Name="玩家二维码")
    messages = maimaiWindow.ListControl(Name="消息")
    if btn.Exists(0, 0):
        maimaiWindow.SetActive()
        maimaiWindow.SetFocus()
        maimaiWindow.SetTopmost()
        btn.Click(simulateMove=False, waitTime=0.1)
        auto.Logger.WriteLine('Clicked!')
    reqTime = datetime.now()
    hour = reqTime.hour
    minute = reqTime.minute
    minute = datetime.now().minute
    now = time.time()
    shouldGet = False
    messageBox = None
    while time.time() - now < 10:
        messages = maimaiWindow.ListControl(Name="消息").GetChildren()
        for message in messages:
            if shouldGet:
                if messages.index(message) == len(messages) - 1:
                    messageBox = message
                    break
            if message.Name in (f"{hour}:{minute:02}", f"{hour}:{minute-1:02}"):
                shouldGet = True
                auto.Logger.WriteLine(f"Found message: {message.Name}")
                continue
        if messageBox:
            break
    pane = messageBox.GetChildren()[0].GetChildren()[1].GetChildren()[0].GetChildren()[0].GetChildren()[0].GetChildren()[0].GetChildren()[1].GetChildren()[2]
    if pane.Exists():
        rect = pane.BoundingRectangle
        left, top, right, bottom = rect.left, rect.top, rect.right, rect.bottom
        now = time.time()
        while time.time() - now < 10:
            screenshot = ImageGrab.grab(
                bbox=(left, top, right, bottom),
                all_screens=True
            )
            enhancer = ImageEnhance.Contrast(screenshot)
            screenshot = enhancer.enhance(2.0)
            screenshot = screenshot.convert('L')
            if is_valid_qrcode(screenshot):
                auto.Logger.WriteLine("Valid QR code detected!")
                break
            else:
                auto.Logger.WriteLine("Invalid QR code detected, retrying...")
                time.sleep(0.5)
        else:
            auto.Logger.WriteLine("Failed to detect QR code in 10 seconds.")
            return
        code = decode(screenshot)[0].data.decode('utf-8')
        print(f"QR code content: {code}")
        expTime = reqTime + timedelta(minutes=10)
        expTimeStr = expTime.strftime("%m/%d %H:%M")

        messageBox.RightClick(simulateMove=False, waitTime=0.1)
        maimaiWindow.MenuControl(ClassName='CMenuWnd').MenuItemControl(Name="删除").Click(simulateMove=False, waitTime=0.1)
        maimaiWindow.WindowControl(ClassName="ConfirmDialog").ButtonControl(Name="确定").Click(simulateMove=False, waitTime=0.1)
        auto.Logger.WriteLine("Message deleted.")
        url = f"{dxpass_url}?maid={code}&time={quote_plus(expTimeStr)}"
        print(f"URL: {url}")
        maimaiWindow.SetTopmost(False)
        nowFocusWindow.SetFocus()
        auto.Logger.WriteLine(f"Completed in {time.time() - handleTime:.2f} s.")
        return code, expTimeStr
    else:
        print("窗格定位失败")
        maimaiWindow.SetTopmost(False)
        nowFocusWindow.SetFocus()


async def handle(request):
    try:
        res = main()
        if res:
            return web.json_response({'maid': res[0], 'time': res[1]})
        return web.Response(text='Failed to get QR code', status=500)
    except Exception as e:
        return web.Response(text=str(e), status=500)


async def htmlPage(request: BaseRequest):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        raise HTTPUnauthorized(text='Authorization header is missing')
    try:
        res = main()
        if res:
            url = f"{dxpass_url}?maid={res[0]}&time={quote_plus(res[1])}"
            completeHtml = html.replace("{final_url}", url)
            return web.Response(text=completeHtml, content_type='text/html')
        return web.Response(text='Failed to get QR code', status=500)
    except Exception as e:
        return web.Response(text=f"{e.__class__.__name__}: {e}", status=500)


async def web_server():
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get('/maimai', handle)
    app.router.add_get(entryPoint, login_handler)
    app.router.add_get('/logout', logout_handler)
    app.router.add_get('/', htmlPage)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', port)
    await site.start()
    
    print(f'Server started at http://127.0.0.1:{port}')
    
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(web_server())
    except KeyboardInterrupt:
        pass