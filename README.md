# UsagiPassQRCodeGetter
用来让你免打开微信公众号，直接通过浏览器获取到登录二维码附加在UsagiPass上，刷新即可使用

# 环境要求
- （推荐）Python 3.12+
- 公网可访问到本程序
- **Windows系统**
- 能够运行微信
- 安装环境遇到问题请首先尝试更新你的老旧依赖，或者询问[DeepSeek](https://chat.deepseek.com/)

# 如何使用？
自行配置下列参数。

**密码一定要修改**

**密码一定要修改**

**密码一定要修改**

重要的事情说三遍！否则下一个被hack的就是你！

在首次运行前修改代码，运行一次后会生成config.ini文件，包含你所更改后的值
```python
entryPoint = "/login"  # 登录页面入口，建议修改以防非法登录
loginUserName = "admin"  # 登录用户名
loginPassword = "maimaidx"  # 登录密码，如果你想被hack的话可以不设置
port = 8080  # 监听端口
dxpass_url = "https://up.turou.fun/"  # 用于显示DXPass的URL
mode: Literal["normal", "marked", "demo"] = "marked"  # 运行模式，normal为正常模式，marked会隐藏敏感信息，demo会替换敏感信息
```

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

2.双击分离窗口，点击一次获取玩家二维码

3.使用手机扫描或截图识别二维码是否能够识别，如果不能识别请拉高缩放比例或者寻找其他能使聊天信息放大方法（笔记本用户2K 200%缩放成功率≈99.9%）

4.成功识别后开始安装所需依赖

```shell
pip install -r requirements.txt
```

5.不要熄灭屏幕/休眠电脑，保持解锁状态。可以通过[这个网站](https://www.keepscreenon.com/)保持亮屏，然后打开 **Python命令行**，在**配置环境**步骤完成后输入以下命令生成一张全屏纯黑图：

```python
from PIL import Image, ImageGrab; img=Image.new('RGB', ImageGrab.grab().size, (0,0,0)); img.save('black.png'); img.show()
```

你可以在运行该程序时全屏此图并降低亮度以避免烧屏，在获取二维码时会自动激活微信窗口


然后输入下列命令启动程序

```shell
python main.py
```

6.打开浏览器，输入`http://127.0.0.1:8080/login` （端口号是8080的话）进行登录，登录成功后会进行一次获取二维码，获取成功则在UsagiPass登录完成后显示二维码和过期时间，否则没有二维码和时间为12：00

7.后续通过`http://127.0.0.1:8080/` 即可获取二维码

8.若要登出，访问`http://127.0.0.1:8080/logout` 后关闭浏览器进程销毁BasicAuth缓存即可。


# 拥有一台公网服务器但是不是Windows无法运行微信？

可以寻找内网穿透工具如ssh，或者使用我的另一个项目[HttpThrouth](https://github.com/MeiHuaGuangShuo/http_through)转发HTTP请求到本地（要求服务器拥有Python环境和公网IP）

# 提供的接口

| 路径 Path     | 功能                                                  |
|-------------|-----------------------------------------------------|
| `/`         | 显示UsagiPass                                         |
| `/login`(可变) | 登录入口                                                |
| `/maimai`   | 获取 `MAID` 和格式化字符串，以 `{'maid': str, 'time': str}` 返回 |
| `/logout`   | 清除浏览器Cookie缓存（执行后需要**关闭浏览器进程**销毁BasicAuth缓存）            |

# 杂谈
这个项目是因为看到了两个项目，一个是UsagiPass，另一个是通过电脑获取二维码并发送到手机应用，我就在想能不能结合一下，然后就诞生了这个项目。

如你所见，本项目除了本地控制微信都是网页，所以你可以专门做一个应用套壳，说不定这样可以让你上机更有逼格