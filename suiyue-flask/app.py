from flask import Flask, render_template, request, jsonify
from SuiYue import suiyue_encode, suiyue_decode

app = Flask(__name__)

# 首页路由
@app.route('/')
def index():
    return render_template('index.html')

# 加密API
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        text = request.form.get('text', '')
        password = request.form.get('password', '')
        is_base64_enabled = request.form.get('is_base64_enabled', 'false') == 'true'
        
        if not text:
            return jsonify({'status': 'error', 'message': '请输入要加密的文本'})
        
        result = suiyue_encode(text, password, is_base64_enabled)
        if result.startswith('Error:'):
            return jsonify({'status': 'error', 'message': result[6:]})
        
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': '加密失败: {}'.format(str(e))})

# 解密API
@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        text = request.form.get('text', '')
        password = request.form.get('password', '')
        
        if not text:
            return jsonify({'status': 'error', 'message': '请输入要解密的文本'})
        
        result = suiyue_decode(text, password)
        if result.startswith('Error:'):
            return jsonify({'status': 'error', 'message': result[6:]})
        
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': '解密失败: {}'.format(str(e))})

if __name__ == '__main__':
    app.run(debug=True)