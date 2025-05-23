# QRcord - 多功能二维码生成器

QRcord 是一个功能丰富的二维码生成器，基于 Python 和 Tkinter 开发，提供了直观的图形界面和强大的功能集。

## ✨ 主要特性

- 🎨 **自定义颜色**
  - 支持自定义二维码填充颜色和背景颜色
  - 支持透明背景选项

- 🔒 **密码保护**
  - 支持对二维码内容进行 AES 加密
  - 内置解密功能，方便查看加密内容
  - 可选择是否显示密码

- 📝 **多行文本支持**
  - 支持输入多行文本内容
  - 实时预览功能

- ⚙️ **丰富的参数设置**
  - 可调整容错级别（L/M/Q/H）
  - 可自定义格子大小
  - 可调整边框宽度

- 🖼️ **多种导出格式**
  - 支持 PNG、JPEG、BMP 等多种图片格式
  - 高质量图像输出

## 🚀 快速开始

### 环境要求
- Python 3.6+
- Tkinter (通常随 Python 一起安装)
- 其他依赖包：
  ```
  pip install qrcode[pil] Pillow pycryptodome
  ```

### 运行方式
```bash
python qr_generator_gui.py
```

## 💡 使用说明

1. **生成二维码**
   - 在文本框中输入要编码的内容
   - 调整参数设置（颜色、大小等）
   - 点击"生成并保存二维码"

2. **密码保护**
   - 勾选"启用密码保护"
   - 输入密码
   - 可选择是否显示密码

3. **解密功能**
   - 在解密区域输入加密数据（以"ENC:"开头）
   - 输入正确的密码
   - 点击"解密数据"查看内容
   - 网页解密：https://qrde.qsct.dpdns.org

## 🔧 技术细节

- 使用 AES-CBC 模式进行加密
- 采用 SHA-256 进行密钥派生// ... existing code ...
import base64

# --- Version ---
__version__ = "1.0.0"

# --- Constants ---
ERROR_LEVELS = {
// ... existing code ...
class QRCodeGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"二维码生成器 v{__version__} (颜色+多行+预览+密码保护+透明背景)")

        self._after_id = None
// ... existing code ...
- 支持 Base64 编码的加密数据

## 📝 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## ⭐ 支持

如果这个项目对你有帮助，欢迎给个 star 支持一下！