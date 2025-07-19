# suiyue-crypto ：文本加解密工具

# 随曰(yuē) - 随心、随意、随时、随地、随曰。

![随曰(yuē)GUI示例图片](images/SuiYue_GUI.jpg "随曰(yuē)GUI界面图")

随曰文本加解密工具网页版测试地址：http://suiyue.67886788.xyz/

![随曰(yuē)HTML示例图片](images/SuiYue_HTML.jpg "随曰(yuē)HTML界面图")

# 随曰文本加解密工具

## 项目简介
"随曰文本加解密工具"是一款基于Python开发的安全加密工具。该工具采用AES和ChaCha20-Poly1305两种高强度加密算法，在保障数据传输安全性的同时，通过Poly1305认证机制确保数据完整性，为用户提供专业级的数据保护解决方案。

## 项目地址
[随曰 SuiYue](https://github.com/zb848/suiyue-crypto)  https://github.com/zb848/suiyue-crypto

[随曰 suiyue](https://pypi.org/project/suiyue)  https://pypi.org/project/suiyue

**注意：** 由于网络原因，链接解析可能失败。如果无法访问，请检查链接的合法性，或稍后重试。

[**exe离线客户端**](https://github.com/zb848/suiyue-crypto/releases)

[**apk安卓客户端**](https://github.com/zb848/suiyue-crypto/releases)

[**网页版 http://suiyue.1o1o.xyz/**](http://suiyue.1o1o.xyz/)

## 功能特点
- 支持 AES-CTR 和 ChaCha20-Poly1305 加密算法。
- 支持标准 Base64 和中文 Base64 编码。
- 提供加密和解密接口。
- 支持错误处理和默认密码。

## 文件说明
suiyue-crypto/                  # 随曰项目根目录

|--SuiYue.py                    # 随曰文本加解密代码，可以单独使用。

|--SuiYue_GUI.py                # 随曰GUI界面代码

|--README.md                    # 随曰说明

|--LICENSE                      # 随曰版权声明

|--images/                      # 随曰图片

|--suiyue-flask/                # 随曰flask网页版项目

#

## 密文示例 (全是水 ^_^ 辨识度应该很高。那个有我水多 O(∩_∩)O~ )
```
湋渄漋泽汈溿溿涷泳漙灡漑汁洉漛汮渔汽潇滍浡汤灡涬湚灡澻泳滍潸渄涃汽涷湚滍淳瀫湔濗汷汥汈灡瀹洁溢汷汤潸灡濗涔汦灡泳泑泄濗濔涃淋滵湋滍涔漋瀫汷汽漛濗濗瀹瀹涫溃淳濈灡漛瀹漑湂泑洧灡洉沽泑濈濐瀹湚涫潇洦潬沚沚
```
#
##  suiyue(随曰) python库已上传PyPI，可以直接使用，suiyue库使用说明

### 安装suiyue库
```
pip install suiyue
```

### 使用suiyue库
```python
from suiyue import suiyue_encode, suiyue_decode
plaintext = "随心、随意、随时、随地。"
password = "随曰"

ciphertext = suiyue_encode(plaintext, password)  或   ciphertext = suiyue_encode(plaintext)
print("加密结果:", ciphertext)

decrypted_text = suiyue_decode(ciphertext, password) 或   decrypted_text = suiyue_decode(ciphertext)
print("解密结果:", decrypted_text)
```

## 版权信息
© 2025 随波逐流 保留所有权利。

## 许可证
[随曰-私下研究专用许可](https://github.com/zb848/suiyue-crypto?tab=License-1-ov-file#)

## 随曰 - 心随性起、意随情生、时随运转、地随缘现、言随风散。