# !/usr/bin/env python
# -*- coding:utf-8 -*-

# @Author :随波逐流
# @Name :随曰文本加解密工具
# @Version :V1.0
# @Vertime :20250718

'''
## 打包代码
pyinstaller --clean --name=SuiYue_GUI -F -w -i favicon.ico SuiYue_GUI.py
'''

import tkinter as tk
from tkinter import scrolledtext, messagebox
import random
import string
import webbrowser
from PIL import Image, ImageTk
import base64
import io

from SuiYue import suiyue_decode, suiyue_encode


ico_png_base64="iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAt1JREFUOE9tk09oXFUUxn/fe+++GrMx1Ng0nTdYm3FmCIoRUUEpBYWCgq4s/gktIi0u3AgiFfyLIBapuhDBClWsFXFhBbvKQqloKVrowpbMNKXBmSQw0SIxVjvvvveOvMFIKz2bcznn3u+e833nCGC2Et9S+uZC+rOBayfxK2D3mGhirJc0gxXHhWbqXf9TeXfNNABIou2RcSmXLsqYCgIdr3XSM2VubtxNZaFeFPYwUmhmb4+k/uWxHhfL/ACgtFY13qEs/aa+xG+X/7B2/qXKyN8WP4t4CewHt+of3PI7KwOAs0m0tfQ3d7PvyhYEfu1hu+LurC/4Hw2Ccwmbc7nXQE+AHW50/LROQxxW3ZPNjv+glcSvI6bNSEOK3Wk3OxFV48My+9NQ14riWgXaiPS4YX6d9zWdqzCREd/dWEg/nU3cMYkjmLaVpJk0KbHD0L6yoijPenkQ3gvahhi3gjfVStxByQ7WO9n3s0n8pWT3Yyxg9pEp2INsBXRUsJN+eh8hsYXugKSthp0qAZYNm252s5lW1R0CThrsCrAvKLK2ye018YeM2xpdP1pW0q66XYY+xlhUqxrPh7k9Vlv0J2YT95kgiVf9dDocPUU/O2lD7hngAtKtzU46OZB2jNE8jpcNjqq9ye2pL/oDAymT+IjydLf7i+H+UNRQqIrBENhpFLzQ7Kbb11QrFBwD3ipbuGPY/PlLYiTHvRFm7MscH2KsDqQUDZlyRN/gE8yuB/ta0udC72p+lLEbf6XXTtypsCj21xbzkocrbG6juz2LeE7SXaG3R/KI5wX7CzShOVjnk7gWyPYaPIDZoyWhV5vGdoVNFrhXw4z3+0v+zCQUg0lsbWBzo8d8K3HvgG4ybIvQVyqKbwuRB9hIofBpYVNhwUMl4Vcs00CacRqB3HX/qvFegFaguADBkop8NQ/UcGl2aKLH8uXV/bdMZfD8DWzIr4nXT3TSs4Lsam38P/YPOjBBY1/JRfwAAAAASUVORK5CYII="

def encrypt_text():
    plaintext = text_input.get("1.0", tk.END).strip()
    if plaintext == "":
        messagebox.showerror("错误", "请输入要加密的文本")
        return
    password = password_entry.get()
    try:
        ciphertext = suiyue_encode(plaintext, password)
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, ciphertext)
    except Exception as e:
        messagebox.showerror("加密错误", "加密过程中出现错误: " + str(e))

def decrypt_text():
    ciphertext = text_input.get("1.0", tk.END).strip()
    if ciphertext == "":
        messagebox.showerror("错误", "请输入要解密的文本")
        return
    password = password_entry.get()
    try:
        plaintext = suiyue_decode(ciphertext, password)
        text_output.delete("1.0", tk.END)
        if plaintext[:6]=="Error:":
            messagebox.showinfo("解密错误", "解密失败:{}".format(plaintext))
            return
        text_output.insert(tk.END, plaintext)
    except Exception as e:
        messagebox.showerror("解密错误", "解密过程中出现错误: " + str(e))

def clear_text():
    text_input.delete("1.0", tk.END)
    text_output.delete("1.0", tk.END)

def copy_result():
    result = text_output.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(result)
    messagebox.showinfo("复制成功", "结果已复制到剪贴板")

def generate_random_password():
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_characters) for i in range(16))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def open_link(link_url):
    webbrowser.open(link_url, new=0, autoraise=True)

# 创建主窗口
root = tk.Tk()
root.title("随曰：开源文本加解密工具 - 随心、随意、随时、随地、随曰。")
root.geometry("800x600")
root.minsize(800, 400)  # 最小尺寸
# 设置窗口图标
# 将 Base64 数据解码为图像
ico_png_data = base64.b64decode(ico_png_base64)
ico_image = Image.open(io.BytesIO(ico_png_data))
# 将图像转换为 Tkinter 可用的 PhotoImage
photo = ImageTk.PhotoImage(ico_image)
# 设置窗口图标
root.iconphoto(False, photo)

root.configure(bg="#f0f0f0")

# 设置字体
font_style = ("微软雅黑", 12)
font_style2 = ("楷体", 10)

# 创建密码框框架
password_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
password_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky=tk.NSEW)
password_frame.columnconfigure(1, weight=1)  # 设置第二列的权重为1，使密码输入框自动缩放

# 密码标签
password_label = tk.Label(password_frame, text="密码:", font=font_style, bg="#f0f0f0")
password_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

# 密码输入框
password_entry = tk.Entry(password_frame, font=font_style)
password_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.EW)

# 随机生成按钮
generate_button = tk.Button(password_frame, text="随机生成", command=generate_random_password, font=font_style, bg="#FFC107", fg="white", padx=5, pady=1)
generate_button.grid(row=0, column=2, padx=5, pady=2)

password_readme = tk.Label(password_frame, text="密码建议：包含大小写字母、数字和特殊符号，长度至少16位；可以点击随机生成按钮。不输入密码将使用默认密码。", font=font_style2, bg="#f0f0f0")
password_readme.grid(row=1, column=0, columnspan=3, padx=10, pady=2, sticky=tk.W)

# 文本输入和输出框架
input_output_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
input_output_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky=tk.NSEW)
input_output_frame.columnconfigure(0, weight=1)
input_output_frame.columnconfigure(1, weight=1)
input_output_frame.rowconfigure(0, weight=0)
input_output_frame.rowconfigure(1, weight=1)

# 文本内容输入框
text_input_label = tk.Label(input_output_frame, text="文本内容", font=font_style, bg="#f0f0f0")
text_input_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
text_input = scrolledtext.ScrolledText(input_output_frame, width=38, height=20, font=font_style, bd=1, relief=tk.SUNKEN)
text_input.grid(row=1, column=0, padx=10, pady=10, sticky=tk.NSEW)

# 输出结果框
text_output_label = tk.Label(input_output_frame, text="输出结果", font=font_style, bg="#f0f0f0")
text_output_label.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
text_output = scrolledtext.ScrolledText(input_output_frame, width=38, height=20, font=font_style, bd=1, relief=tk.SUNKEN)
text_output.grid(row=1, column=1, padx=10, pady=10, sticky=tk.NSEW)

help_readme = tk.Label(input_output_frame, text="所有操作均在本软件内完成；请妥善保存密码，丢失将无法解密数据。", font=font_style2, bg="#f0f0f0")
help_readme.grid(row=2, column=0, columnspan=3, padx=10, pady=2, sticky=tk.W)


# 按钮框架
button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
button_frame.columnconfigure(0, weight=1)  # 设置按钮框架列权重以实现居中

# 加密按钮
encrypt_button = tk.Button(button_frame, text="加  密", command=encrypt_text, font=font_style, bg="#4CAF50", fg="white", padx=20, pady=5)
encrypt_button.pack(side=tk.LEFT, padx=10, expand=True)

# 解密按钮
decrypt_button = tk.Button(button_frame, text="解  密", command=decrypt_text, font=font_style, bg="#2196F3", fg="white", padx=20, pady=5)
decrypt_button.pack(side=tk.LEFT, padx=10, expand=True)

# 清空按钮
clear_button = tk.Button(button_frame, text="清  空", command=clear_text, font=font_style, bg="#FF5722", fg="white", padx=20, pady=5)
clear_button.pack(side=tk.LEFT, padx=10, expand=True)

# 复制结果按钮
copy_button = tk.Button(button_frame, text="复制结果", command=copy_result, font=font_style, bg="#FFC107", fg="white", padx=20, pady=5)
copy_button.pack(side=tk.LEFT, padx=10, expand=True)

# 底部框架
end_frame = tk.Frame(root, bg="#f0f0f0")
end_frame.grid(row=3, column=0, columnspan=3, padx=2, pady=2, sticky="ew")

# 设置 end_frame 列权重，让第 1 列自适应大小
end_frame.columnconfigure(0, weight=0)
end_frame.columnconfigure(1, weight=1)
end_frame.columnconfigure(2, weight=0)  # 第 2 列权重为 0，不会自动扩展

# 创建一个标签显示图标
img_label = tk.Label(end_frame, image=photo)
# 使用 sticky="w" 让标签靠左
img_label.grid(row=0, column=0, padx=2, pady=2, sticky="w")

# 创建一个标签显示软件说明
soft_readme = tk.Label(end_frame, text="随曰(yuē) - 心随性起、意随情生、时随运转、地随缘现、言随风散。", font=font_style2, bg="#f0f0f0")
# 使用 sticky="w" 让标签靠左
soft_readme.grid(row=0, column=1, padx=2, pady=2, sticky="w")

# 创建一个标签显示作者信息
author_readme = tk.Label(end_frame, text="随波逐流作品 © Github", font=font_style2, bg="#f0f0f0")
# 使用 sticky="e" 让标签靠右，column=2 占据第二列，由于该列权重为 0，不会自动扩展
author_readme.grid(row=0, column=2, padx=2, pady=2, sticky="e")
author_readme.bind("<Button-1>", lambda event: webbrowser.open("https://github.com/zb848/suiyue-crypto"))

# 创建右键菜单
def create_context_menu(widget):
    context_menu = tk.Menu(widget, tearoff=0)
    context_menu.add_command(label="复制", command=lambda: widget.event_generate("<<Copy>>"))
    context_menu.add_command(label="剪切", command=lambda: widget.event_generate("<<Cut>>"))
    context_menu.add_command(label="粘贴", command=lambda: widget.event_generate("<<Paste>>"))

    def show_context_menu(event):
        context_menu.post(event.x_root, event.y_root)

    widget.bind("<Button-3>", show_context_menu)

# 为文本框添加右键菜单
create_context_menu(password_entry)
create_context_menu(text_input)
create_context_menu(text_output)

# 设置窗口的列和行权重，使组件可以自适应窗口大小
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=1)
root.rowconfigure(1, weight=1)




# 运行主循环
root.mainloop()