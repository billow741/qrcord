function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const showPasswordCheckbox = document.getElementById('showPassword');
    passwordInput.type = showPasswordCheckbox.checked ? 'text' : 'password';
}

function decryptData() {
    const encryptedData = document.getElementById('encryptedData').value.trim();
    const password = document.getElementById('password').value.trim();
    const resultDiv = document.getElementById('result');
    const errorDiv = document.getElementById('error');

    // 重置显示
    resultDiv.style.display = 'none';
    errorDiv.style.display = 'none';

    // 验证输入
    if (!encryptedData) {
        showError('请输入加密数据');
        return;
    }
    if (!password) {
        showError('请输入解密密码');
        return;
    }

    try {
        // 检查是否是加密数据
        if (!encryptedData.startsWith('ENC:')) {
            showError('这不是有效的加密数据');
            return;
        }

        // 移除ENC:前缀
        const data = encryptedData.substring(4);

        // 使用密码生成密钥
        const key = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex).substring(0, 32);
        
        // 解码base64数据
        const encrypted = CryptoJS.enc.Base64.parse(data);
        
        // 分离IV和加密数据
        const iv = CryptoJS.lib.WordArray.create(encrypted.words.slice(0, 4));
        const encryptedContent = CryptoJS.lib.WordArray.create(encrypted.words.slice(4));
        
        // 解密
        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: encryptedContent },
            CryptoJS.enc.Hex.parse(key),
            {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }
        );

        // 显示解密结果
        const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
        if (!decryptedText) {
            showError('解密失败：密码错误或数据已损坏');
            return;
        }

        resultDiv.textContent = decryptedText;
        resultDiv.style.display = 'block';

    } catch (error) {
        showError('解密失败：' + error.message);
    }
}

function showError(message) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
} 