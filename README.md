# UsagiPassQRCodeGetter
用来让你免打开微信公众号，直接通过浏览器获取到登录二维码附加在UsagiPass上，刷新即可使用，
或是让你无手机出勤（借手机嘛，起码不用登录微信），或者...单片机出勤可能！

超快获取二维码速度（2.3~3秒），延迟基本来源于网络延迟，使用同省内网穿透可3秒左右获取二维码

# 环境要求
- （推荐）Python 3.12+
- 公网可访问到本程序（或者使用内网穿透）
- **Windows系统**
- 能够运行微信（版本 >= 4.0.0）
- 安装环境遇到问题请首先尝试更新你的老旧依赖，或者询问[DeepSeek](https://chat.deepseek.com/),[豆包](https://doubao.com/)

# 如何使用？
自行配置下列参数。

**密码一定要修改**

**密码一定要修改**

**密码一定要修改**

重要的事情说三遍！否则下一个被发牌的就是你！

修改登录入口为非默认入口后，将不会自动重定向到登录入口，请牢记登录地址。
登录现在可以配置CapJS验证码防止简单的密码爆破。如何使用请查看[增加登录安全性](#增加登录安全性)

在首次运行前修改代码，运行一次后会生成config.ini文件，包含你所更改后的值
```python
entryPoint = "/login"  # 登录页面入口，建议修改以防非法登录
loginUserName = "admin"  # 登录用户名
loginPassword = "maimaidx"  # 登录密码，如果你想被hack的话可以不设置
port = 8080  # 监听端口
dxpass_url = "https://up.turou.fun/"  # 用于显示DXPass的URL
mode: Literal["normal", "marked", "demo", "web_only"] = "marked"  # 运行模式，normal为正常模式，marked会隐藏敏感信息，demo会替换敏感信息，web_only只显示DXPass页面
```

对于使用`demo`和`web_only`模式产生的二维码可随意发放，作为演示使用，此模式产生的二维码基于时间或原二维码哈希后生成

后续可以在 `config.ini` 文件修改配置

```ini
[Default]
# 登录页面入口，建议修改以防非法登录
entryPoint = /login
# 登录用户名
loginUserName = admin
# 登录密码
loginPassword = maimaidx
# 监听端口 (1-65535)
port = 8080
# 用于显示DXPass的URL
dxpass_url = https://up.turou.fun/
# 运行模式，normal为正常模式，marked会隐藏敏感信息，demo会替换敏感信息
mode = marked
```

1.打开微信，找到“舞萌 | 中二”公众号

2.双击侧边栏分离公众号窗口，点击一次获取玩家二维码

3.使用手机扫描或截图识别二维码是否能够识别，如果不能识别请拉高缩放比例或者寻找其他能使聊天信息放大方法（笔记本用户2K 200%缩放成功率≈99.9%）。
微信使用Qt框架，你可以以此去寻找可用的方法。

4.成功识别后开始安装所需依赖

```shell
pip install -r requirements.txt
```

5.不要熄灭屏幕/睡眠/休眠电脑，保持解锁状态，如果使用的动态锁的用户请关闭蓝牙避免自动锁定。（以下可选）

> 打开 **Python命令行**，在**配置环境**步骤完成后输入以下命令生成一张全屏纯黑图：
> 
> ```python
> from PIL import Image, ImageGrab; img=Image.new('RGB', ImageGrab.grab().size, (0,0,0)); img.save('black.png'); img.show()
> ```
> 
> 你可以在运行该程序时全屏此图并降低亮度以避免烧屏，在获取二维码时会自动激活微信窗口。
> 获取时仅需控制鼠标进行单次点击，所以运行此程序时也可以进行轻度办公。


然后输入下列命令启动程序测试是否可以获取到二维码

```shell
python main.py 1
```

如果你发现输出中没有类似 `Traceback` 的内容且打印出获取到的二维码内容（`Code: MAID...`）则
代表程序能够正常运行，此时使用以下命令启动服务端

```shell
python main.py
```

6.打开浏览器，输入`http://127.0.0.1:8080/login` （端口号是8080的话）进行登录，
默认用户名`admin`，密码`maimaidx`，登录成功后会进行一次获取二维码，获取成功则在UsagiPass登录完成后显示二维码和过期时间，否则没有二维码和时间为12：00。
如果你不想使用UsagePass，而是使用和官方类似的界面，请访问`http://127.0.0.1:8080/qrc` 
登录支持多设备登录，重启程序后销毁

7.后续通过`http://127.0.0.1:8080/` 即可获取二维码。`舞萌 | 中二`窗口可以最小化，会自动还原，但是不能关闭

8.若要登出，访问`http://127.0.0.1:8080/logout` 即可。


# 增加登录安全性

为了防止可能的简单爆破，引入了 [CapJS](https://capjs.js.org/) 作为一种预防措施。此功能依赖于 Cloudflare Worker。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xyTom/cap-worker)

使用上方的按钮在Cloudflare部署服务端。为了能让国内的用户正常访问，建议使用自定义域名绑定到已有域名。

部署选择 连接GitHub ，勾选专用存储库，然后部署。在 `Worker` -> `设置` -> `域和路由` 找到
部署的域名，复制后填入 `config.ini` 的 `capjs_endpoint` 项，一定要加上 `https://` 开头

如果一切正常，重启程序后即可查看到登录页面显示CapJS验证码且可以成功验证。


默认通过浏览器指纹进行登录次数限制，但是本方法极其容易被绕过，因此仅作为保底。

对于公开网络，修改登录入口为复杂的入口，使用复杂的账号密码，启用验证码可以为您提供足够的安全性

登录二维码在获取后10分钟内有效，可登录状态在获取后30分钟内有效。如果您使用录屏，请确保发布时间
大于30分钟或者使用 `demo` / `web_only` 模式在客户端生成无法登录的二维码

# 没有公网服务器？

1. 可以寻找内网穿透工具如ssh，或者使用我的另一个项目[HttpThrouth](https://github.com/MeiHuaGuangShuo/http_through)转发HTTP请求到本地（要求服务器拥有Python环境和公网IP）

2. 可以使用[SakuraFrp](https://www.natfrp.com/)内网穿透，在 `用户界面` -> `服务` -> `子域绑定` 处
 **绑定域名** 后下载证书，将证书放置在本程序同目录下，修改 `config.ini` 文件中的 `certfile` 和 `keyfile` 路径为证书文件名和密钥文件名，然后运行程序即可。在指定了证书的情况下程序会运行在HTTPS模式，
并且会在控制台打印出 `SSL enabled`

3. 如果有Cloudflare托管域名的话也可以使用Tunnel进行内网穿透

# 提供的接口

| 路径 Path       | 功能                                                  |
|---------------|-----------------------------------------------------|
| `/`           | 显示UsagiPass，获取到二维码时会立即先显示简单的页面避免无法加载，然后再显示UsagiPass |
| `/qrc`        | 获取简单的登录二维码                                          |
| `/login`(可变)  | 登录入口                                                |
| `/maimai`     | 获取 `MAID` 和格式化字符串，以 `{'maid': str, 'time': str}` 返回 |
| `/logout`     | 清除浏览器Cookie缓存和服务端缓存，并退出登录                           |
| `/logout_all` | 将全部登录设备强制取消登录，包括此设备，需要登录后使用                         | 

# 部分资源来源

1. [UsagiPass](https://github.com/TrueRou/UsagiPass) - 用于显示DXPass
2. [青葉もち](https://www.pixiv.net/users/27236214) - 使用了其创作的图片作为网页背景

如果您不愿意您的资源被本项目使用，请通过Issue联系我进行删除。

# 杂谈
这个项目是因为看到了两个项目，一个是UsagiPass，另一个是通过电脑获取二维码并发送到手机应用，我就在想能不能结合一下，然后就诞生了这个项目。

如你所见，本项目除了本地控制微信都是网页，所以你可以专门做一个应用套壳，说不定这样可以让你上机更有逼格
