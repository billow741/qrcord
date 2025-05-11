import tkinter as tk
from tkinter import ttk, filedialog, messagebox, colorchooser # <--- 导入 colorchooser
import qrcode
from PIL import Image, ImageTk
import os
import io
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# --- Constants ---
ERROR_LEVELS = {
    'L (低 ~7%)': qrcode.constants.ERROR_CORRECT_L,
    'M (中 ~15%)': qrcode.constants.ERROR_CORRECT_M,
    'Q (较高 ~25%)': qrcode.constants.ERROR_CORRECT_Q,
    'H (高 ~30%)': qrcode.constants.ERROR_CORRECT_H
}
DEFAULT_ERROR_LEVEL_KEY = 'M (中 ~15%)'
PREVIEW_MAX_SIZE = 250
DEBOUNCE_DELAY_MS = 500
DEFAULT_FILL_COLOR = "#000000" # Black
DEFAULT_BACK_COLOR = "#FFFFFF" # White
TRANSPARENT_COLOR = "透明" # 透明背景标识

class QRCodeGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("二维码生成器 (颜色+多行+预览+密码保护+透明背景)")

        self._after_id = None

        # --- 颜色变量 ---
        self.fill_color_var = tk.StringVar(value=DEFAULT_FILL_COLOR)
        self.back_color_var = tk.StringVar(value=DEFAULT_BACK_COLOR)
        
        # --- 密码变量 ---
        self.password_var = tk.StringVar()
        self.use_password_var = tk.BooleanVar(value=False)
        self.show_password_var = tk.BooleanVar(value=False)

        # --- 主框架 ---
        main_frame = ttk.Frame(root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        # --- 左右框架 ---
        left_frame = ttk.Frame(main_frame, padding="10")
        left_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W, tk.E))
        main_frame.columnconfigure(0, weight=1)
        right_frame = ttk.Frame(main_frame, padding="10")
        right_frame.grid(row=0, column=1, sticky=(tk.N, tk.S, tk.W, tk.E))
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)

        # --- 输入数据 (多行文本) ---
        ttk.Label(left_frame, text="输入数据 (URL 或文本, 支持多行):").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5)
        )
        text_frame = ttk.Frame(left_frame)
        text_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        left_frame.rowconfigure(1, weight=1)
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        self.data_entry = tk.Text(text_frame, wrap=tk.WORD, height=10, width=40, undo=True)
        self.data_entry.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.data_entry.focus()
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.data_entry.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.data_entry.config(yscrollcommand=scrollbar.set)
        self.data_entry.bind("<KeyRelease>", self.schedule_preview_update)

        # --- 参数设置 ---
        options_frame = ttk.LabelFrame(left_frame, text="参数设置", padding="10")
        options_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        options_frame.columnconfigure(1, weight=1) # Give space for controls

        row_idx = 0 # Keep track of grid row

        # 密码保护
        password_frame = ttk.Frame(options_frame)
        password_frame.grid(row=row_idx, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        password_check = ttk.Checkbutton(password_frame, text="启用密码保护", 
                                       variable=self.use_password_var,
                                       command=self.toggle_password_field)
        password_check.pack(side=tk.LEFT)
        
        # 创建密码输入框和显示密码复选框的容器
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(side=tk.LEFT, padx=(5, 0))
        
        self.password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, 
                                      show="*", state="disabled", width=20)
        self.password_entry.pack(side=tk.LEFT)
        self.password_entry.bind("<KeyRelease>", self.schedule_preview_update)
        
        # 添加显示密码复选框
        show_password_check = ttk.Checkbutton(password_input_frame, text="显示密码",
                                            variable=self.show_password_var,
                                            command=self.toggle_password_visibility)
        show_password_check.pack(side=tk.LEFT, padx=(5, 0))
        row_idx += 1

        # 容错级别
        ttk.Label(options_frame, text="容错级别:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=5)
        self.error_var = tk.StringVar(value=DEFAULT_ERROR_LEVEL_KEY)
        error_combo = ttk.Combobox(options_frame, textvariable=self.error_var,
                                   values=list(ERROR_LEVELS.keys()), state="readonly", width=15)
        error_combo.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=5)
        error_combo.bind("<<ComboboxSelected>>", self.schedule_preview_update)
        row_idx += 1

        # 格子大小
        ttk.Label(options_frame, text="格子大小:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=5)
        self.box_size_var = tk.IntVar(value=10)
        box_size_spinbox = ttk.Spinbox(options_frame, from_=1, to=50,
                                      textvariable=self.box_size_var, width=5,
                                      command=self.schedule_preview_update_from_widget)
        box_size_spinbox.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=5)
        row_idx += 1

        # 边框宽度
        ttk.Label(options_frame, text="边框宽度:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=5)
        self.border_var = tk.IntVar(value=4)
        border_spinbox = ttk.Spinbox(options_frame, from_=0, to=20,
                                    textvariable=self.border_var, width=5,
                                    command=self.schedule_preview_update_from_widget)
        border_spinbox.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=5)
        row_idx += 1

        # --- 颜色选择 ---
        # 填充颜色 (Foreground)
        ttk.Label(options_frame, text="填充颜色:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=5)
        fill_color_frame = ttk.Frame(options_frame) # Frame to hold button and display
        fill_color_frame.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=5)

        self.fill_color_display = tk.Label(fill_color_frame, width=4, relief=tk.SUNKEN, borderwidth=1)
        self.fill_color_display.pack(side=tk.LEFT, padx=(0, 5))
        fill_color_button = ttk.Button(fill_color_frame, text="选择...", command=lambda: self.choose_color('fill'))
        fill_color_button.pack(side=tk.LEFT)
        row_idx += 1

        # 背景颜色 (Background)
        ttk.Label(options_frame, text="背景颜色:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=5)
        back_color_frame = ttk.Frame(options_frame) # Frame to hold button and display
        back_color_frame.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=5)

        self.back_color_display = tk.Label(back_color_frame, width=4, relief=tk.SUNKEN, borderwidth=1)
        self.back_color_display.pack(side=tk.LEFT, padx=(0, 5))
        back_color_button = ttk.Button(back_color_frame, text="选择...", command=lambda: self.choose_color('back'))
        back_color_button.pack(side=tk.LEFT)
        
        # 添加透明背景复选框
        self.transparent_var = tk.BooleanVar(value=False)
        transparent_check = ttk.Checkbutton(back_color_frame, text="透明背景", 
                                          variable=self.transparent_var,
                                          command=self.toggle_transparent)
        transparent_check.pack(side=tk.LEFT, padx=(5, 0))
        row_idx += 1

        # --- 生成保存按钮 ---
        save_button = ttk.Button(left_frame, text="生成并保存二维码", command=self.save_qr_code)
        save_button.grid(row=3, column=0, columnspan=2, pady=(15, 0))

        # --- 预览区域 ---
        preview_label_frame = ttk.LabelFrame(right_frame, text="预览", padding="10")
        preview_label_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W, tk.E))
        right_frame.rowconfigure(0, weight=1)
        right_frame.columnconfigure(0, weight=1)
        
        # 设置预览窗口的固定大小
        preview_canvas = tk.Canvas(preview_label_frame, width=300, height=300, bg='white')
        preview_canvas.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W, tk.E))
        preview_label_frame.rowconfigure(0, weight=1)
        preview_label_frame.columnconfigure(0, weight=1)
        
        self.preview_label = ttk.Label(preview_canvas, text="输入数据以生成预览", anchor=tk.CENTER, background="white")
        self.preview_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.qr_photo_image = None

        # --- 状态栏 ---
        self.status_var = tk.StringVar(value="准备就绪")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        # --- 解密区域 ---
        decrypt_frame = ttk.LabelFrame(main_frame, text="解密加密数据", padding="10")
        decrypt_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # 加密数据输入
        ttk.Label(decrypt_frame, text="加密数据:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.encrypted_data_entry = ttk.Entry(decrypt_frame, width=40)
        self.encrypted_data_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 解密密码输入框架
        decrypt_password_frame = ttk.Frame(decrypt_frame)
        decrypt_password_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # 解密密码标签
        ttk.Label(decrypt_password_frame, text="解密密码:").pack(side=tk.LEFT)
        
        # 解密密码输入框
        self.decrypt_password_entry = ttk.Entry(decrypt_password_frame, show="*", width=40)
        self.decrypt_password_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # 显示密码复选框
        self.show_decrypt_password_var = tk.BooleanVar(value=False)
        show_decrypt_password_check = ttk.Checkbutton(decrypt_password_frame, text="显示密码",
                                                    variable=self.show_decrypt_password_var,
                                                    command=self.toggle_decrypt_password_visibility)
        show_decrypt_password_check.pack(side=tk.LEFT, padx=(5, 0))
        
        # 解密按钮
        decrypt_button = ttk.Button(decrypt_frame, text="解密数据", command=self.decrypt_data_from_entry)
        decrypt_button.grid(row=2, column=0, columnspan=2, pady=(5, 0))

        # --- 初始化 ---
        self.update_color_display('fill', self.fill_color_var.get()) # Set initial display color
        self.update_color_display('back', self.back_color_var.get()) # Set initial display color
        self.update_preview() # Initial call

    def toggle_password_visibility(self):
        """切换密码显示/隐藏"""
        if self.password_entry.cget("state") != "disabled":
            if self.show_password_var.get():
                self.password_entry.config(show="")
            else:
                self.password_entry.config(show="*")

    def toggle_password_field(self):
        """启用或禁用密码输入框"""
        if self.use_password_var.get():
            self.password_entry.config(state="normal")
            # 保持当前的显示/隐藏状态
            if self.show_password_var.get():
                self.password_entry.config(show="")
            else:
                self.password_entry.config(show="*")
        else:
            self.password_var.set("")
            self.password_entry.config(state="disabled")
            # 重置显示密码选项
            self.show_password_var.set(False)
        self.schedule_preview_update()

    def encrypt_data(self, data, password):
        """使用AES加密数据"""
        try:
            # 使用密码生成密钥 (与JavaScript保持一致)
            key = hashlib.sha256(password.encode()).hexdigest()[:32]
            key_bytes = bytes.fromhex(key)
            # 生成随机IV
            iv = os.urandom(16)
            # 创建AES加密器
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            # 加密数据
            encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
            # 将IV和加密数据组合并转换为base64
            combined = iv + encrypted_data
            return base64.b64encode(combined).decode()
        except Exception as e:
            raise Exception(f"加密失败: {str(e)}")

    def decrypt_data(self, encrypted_data, password):
        """使用AES解密数据"""
        try:
            # 解码base64数据
            combined = base64.b64decode(encrypted_data)
            # 分离IV和加密数据
            iv = combined[:16]
            encrypted = combined[16:]
            # 使用密码生成密钥 (与JavaScript保持一致)
            key = hashlib.sha256(password.encode()).hexdigest()[:32]
            key_bytes = bytes.fromhex(key)
            # 创建AES解密器
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            # 解密数据
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"解密失败：{str(e)}")

    def get_input_data(self):
        """获取输入数据，如果启用了密码保护则加密数据"""
        data = self.data_entry.get("1.0", tk.END).strip()
        if self.use_password_var.get() and self.password_var.get():
            try:
                # 加密数据
                encrypted_data = self.encrypt_data(data, self.password_var.get())
                # 添加标识符
                return f"ENC:{encrypted_data}"
            except Exception as e:
                messagebox.showerror("加密错误", str(e))
                return data
        return data

    def schedule_preview_update(self, *args):
        """安排预览更新，添加密码输入框的绑定"""
        if self._after_id:
            self.root.after_cancel(self._after_id)
        self._after_id = self.root.after(DEBOUNCE_DELAY_MS, self.update_preview)

    def schedule_preview_update_from_widget(self):
        self.schedule_preview_update()

    # --- 新增：颜色选择逻辑 ---
    def choose_color(self, color_type):
        """ 打开颜色选择器并更新颜色 """
        if color_type == 'back' and self.transparent_var.get():
            messagebox.showinfo("提示", "请先取消透明背景选项")
            return
            
        current_color = self.fill_color_var.get() if color_type == 'fill' else self.back_color_var.get()
        # askcolor returns (rgb_tuple, hex_string) or (None, None)
        color_info = colorchooser.askcolor(initialcolor=current_color, title=f"选择{'填充' if color_type == 'fill' else '背景'}颜色")

        hex_color = color_info[1] # Get the hex string

        if hex_color: # Check if a color was chosen (didn't cancel)
            if color_type == 'fill':
                self.fill_color_var.set(hex_color)
                self.update_color_display('fill', hex_color)
            else: # 'back'
                self.back_color_var.set(hex_color)
                self.update_color_display('back', hex_color)
            # 更新预览
            self.schedule_preview_update()

    def update_color_display(self, color_type, hex_color):
        """ 更新颜色显示标签的外观 """
        display_label = self.fill_color_display if color_type == 'fill' else self.back_color_display
        try:
            display_label.config(background=hex_color)
            # Optional: Set text color for better contrast (simple brightness check)
            # text_color = self.get_text_color(hex_color)
            # display_label.config(text=hex_color, fg=text_color) # Display hex code too
        except tk.TclError:
            # Handle invalid color string if needed, though askcolor should return valid hex
            print(f"无效的颜色值: {hex_color}")

    # Optional helper for text contrast
    # def get_text_color(self, hex_color):
    #     """ Choose black or white text based on background brightness """
    #     try:
    #         hex_color = hex_color.lstrip('#')
    #         r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    #         brightness = (r * 299 + g * 587 + b * 114) / 1000
    #         return "#FFFFFF" if brightness < 128 else "#000000" # White on dark, Black on light
    #     except:
    #         return "#000000" # Default to black on error

    # --- 修改：预览更新 ---
    def update_preview(self):
        self._after_id = None
        data = self.get_input_data()
        fill_color = self.fill_color_var.get()
        back_color = self.back_color_var.get()

        if not data:
            self.preview_label.config(image='', text="输入数据以生成预览", background="white")
            self.qr_photo_image = None
            self.status_var.set("请输入数据")
            return

        try:
            self.status_var.set("正在生成预览...")
            self.root.update_idletasks()

            qr = qrcode.QRCode(
                version=None,
                error_correction=ERROR_LEVELS.get(self.error_var.get(), ERROR_LEVELS[DEFAULT_ERROR_LEVEL_KEY]),
                box_size=self.box_size_var.get(),
                border=self.border_var.get(),
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # 处理透明背景
            if self.transparent_var.get():
                # 先生成白色背景的二维码
                img_pil = qr.make_image(fill_color=fill_color, back_color="#FFFFFF")
                # 将白色背景转换为透明
                img_pil = img_pil.convert("RGBA")
                data = img_pil.getdata()
                new_data = []
                for item in data:
                    # 如果像素是白色，则设置为透明
                    if item[0] == 255 and item[1] == 255 and item[2] == 255:
                        new_data.append((255, 255, 255, 0))
                    else:
                        new_data.append(item)
                img_pil.putdata(new_data)
            else:
                img_pil = qr.make_image(fill_color=fill_color, back_color=back_color)

            # 调整图片大小以适应预览窗口
            img_pil.thumbnail((280, 280), Image.Resampling.LANCZOS)
            self.qr_photo_image = ImageTk.PhotoImage(img_pil)
            
            # 添加密码保护标识
            if self.use_password_var.get() and self.password_var.get():
                self.preview_label.config(image=self.qr_photo_image, text="", background="white")
                # 在预览下方添加密码保护提示
                self.status_var.set("预览已更新 (已启用密码保护 - 请使用QR码生成器解密)")
            else:
                self.preview_label.config(image=self.qr_photo_image, text="", background="white")
                self.status_var.set("预览已更新")

        except qrcode.exceptions.DataOverflowError:
             self.preview_label.config(image='', text="错误：数据过多\n请减少数据量\n或提高容错级别", background="white")
             self.qr_photo_image = None
             self.status_var.set("错误：数据过多")
        except Exception as e:
            error_short = str(e).split('\n')[0]
            self.preview_label.config(image='', text=f"预览生成错误:\n{error_short[:50]}...", background="white")
            self.qr_photo_image = None
            self.status_var.set(f"错误: {error_short[:50]}...")

    # --- 修改：保存功能 ---
    def save_qr_code(self):
        data = self.get_input_data()
        fill_color = self.fill_color_var.get()
        back_color = self.back_color_var.get()

        if not data:
            messagebox.showerror("错误", "请输入要编码的数据！")
            self.status_var.set("错误：数据为空")
            return

        # 检查密码是否已设置
        if self.use_password_var.get() and not self.password_var.get():
            messagebox.showerror("错误", "已启用密码保护，请输入密码！")
            self.status_var.set("错误：密码为空")
            return

        # 简单的颜色对比度检查（可选，但推荐）
        if not self.transparent_var.get() and fill_color.lower() == back_color.lower():
            if not messagebox.askyesno("颜色警告", f"填充颜色 ({fill_color}) 和背景颜色 ({back_color}) 相同。\n生成的二维码可能无法被扫描。\n是否仍然继续保存？"):
                self.status_var.set("保存操作因颜色相同而取消")
                return

        filename = filedialog.asksaveasfilename(
            title="保存二维码为",
            defaultextension=".png",
            filetypes=[("PNG 图像", "*.png"), ("JPEG 图像", "*.jpg;*.jpeg"), ("BMP 图像", "*.bmp"), ("所有文件", "*.*")]
        )
        if not filename:
            self.status_var.set("保存操作已取消")
            return

        try:
            self.status_var.set("正在生成最终图像...")
            self.root.update_idletasks()

            qr = qrcode.QRCode(
                version=None,
                error_correction=ERROR_LEVELS.get(self.error_var.get(), ERROR_LEVELS[DEFAULT_ERROR_LEVEL_KEY]),
                box_size=self.box_size_var.get(),
                border=self.border_var.get(),
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            # 处理透明背景
            if self.transparent_var.get():
                # 先生成白色背景的二维码
                img_pil = qr.make_image(fill_color=fill_color, back_color="#FFFFFF")
                # 将白色背景转换为透明
                img_pil = img_pil.convert("RGBA")
                data = img_pil.getdata()
                new_data = []
                for item in data:
                    # 如果像素是白色，则设置为透明
                    if item[0] == 255 and item[1] == 255 and item[2] == 255:
                        new_data.append((255, 255, 255, 0))
                    else:
                        new_data.append(item)
                img_pil.putdata(new_data)
            else:
                img_pil = qr.make_image(fill_color=fill_color, back_color=back_color)

            img_pil.save(filename)
            messagebox.showinfo("成功", f"二维码已成功保存为:\n{filename}")
            self.status_var.set(f"已保存: {os.path.basename(filename)}")

        except qrcode.exceptions.DataOverflowError:
             messagebox.showerror("保存失败", "数据对于当前设置（格子大小、容错级别）来说太长了。\n请尝试减少数据量、增大格子大小或提高容错级别。")
             self.status_var.set("错误：数据过多，保存失败")
        except Exception as e:
            messagebox.showerror("保存失败", f"生成或保存二维码时发生错误:\n{e}")
            self.status_var.set("错误：保存失败")

    def decrypt_data_from_entry(self):
        """从输入框解密数据"""
        encrypted_data = self.encrypted_data_entry.get().strip()
        password = self.decrypt_password_entry.get().strip()
        
        if not encrypted_data:
            messagebox.showerror("错误", "请输入要解密的数据！")
            return
            
        if not password:
            messagebox.showerror("错误", "请输入解密密码！")
            return
            
        try:
            # 检查是否是加密数据
            if not encrypted_data.startswith("ENC:"):
                messagebox.showerror("错误", "这不是有效的加密数据！")
                return
                
            # 移除ENC:前缀
            encrypted_data = encrypted_data[4:]
            
            # 解密数据
            decrypted_data = self.decrypt_data(encrypted_data, password)
            
            # 显示解密结果
            result_window = tk.Toplevel(self.root)
            result_window.title("解密结果")
            result_window.geometry("400x300")
            
            # 创建文本框显示解密结果
            text_frame = ttk.Frame(result_window, padding="10")
            text_frame.pack(fill=tk.BOTH, expand=True)
            
            result_text = tk.Text(text_frame, wrap=tk.WORD, height=10, width=40)
            result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            result_text.insert("1.0", decrypted_data)
            result_text.config(state="disabled")
            
            scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=result_text.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            result_text.config(yscrollcommand=scrollbar.set)
            
            # 添加复制按钮
            def copy_to_clipboard():
                self.root.clipboard_clear()
                self.root.clipboard_append(decrypted_data)
                messagebox.showinfo("成功", "已复制到剪贴板！")
                
            copy_button = ttk.Button(result_window, text="复制到剪贴板", command=copy_to_clipboard)
            copy_button.pack(pady=10)
            
        except ValueError as e:
            messagebox.showerror("解密失败", str(e))
        except Exception as e:
            messagebox.showerror("解密失败", f"解密过程中发生错误：{str(e)}")

    def toggle_transparent(self):
        """切换透明背景"""
        if self.transparent_var.get():
            self.back_color_var.set(TRANSPARENT_COLOR)
            self.back_color_display.config(background="SystemButtonFace")
        else:
            self.back_color_var.set(DEFAULT_BACK_COLOR)
            self.update_color_display('back', DEFAULT_BACK_COLOR)
        self.schedule_preview_update()

    def toggle_decrypt_password_visibility(self):
        """切换解密密码显示/隐藏"""
        if self.show_decrypt_password_var.get():
            self.decrypt_password_entry.config(show="")
        else:
            self.decrypt_password_entry.config(show="*")

# --- 主程序入口 (保持不变) ---
if __name__ == "__main__":
    # 依赖检查
    try:
        import qrcode
        from PIL import Image, ImageTk
        import tkinter.colorchooser # Check explicitly
    except ImportError as e:
        root_check = tk.Tk()
        root_check.withdraw()
        missing_module = "未知"
        if 'qrcode' in str(e): missing_module = "'qrcode'"
        elif 'PIL' in str(e): missing_module = "'Pillow'"
        elif 'colorchooser' in str(e): missing_module = "'tkinter.colorchooser' (通常随 Tkinter 一起提供)"

        messagebox.showerror("依赖错误", f"必需的模块 {missing_module} 未找到。\n请确保已安装 'qrcode[pil]' 和 'Pillow'。\n(命令: pip install qrcode[pil] Pillow)")
        root_check.destroy()
        import sys
        sys.exit(1)

    root = tk.Tk()
    app = QRCodeGeneratorApp(root)
    root.mainloop()