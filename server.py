from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sock import Sock
from models import register_user, TaiKhoan, Khoa, get_engine
from werkzeug.security import check_password_hash
from sqlalchemy.orm import sessionmaker

import base64
import json
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5  # Thêm import
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = 'super-secret-key'
sock = Sock(app)

engine = get_engine()
Session = sessionmaker(bind=engine)
clients = {}  # {username: ws}

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        ten_dang_nhap = request.form['username']
        mat_khau = request.form['password']
        ten_nguoi_dung = request.form['fullname']

        if register_user(ten_dang_nhap, mat_khau, ten_nguoi_dung):
            flash('✅ Đăng ký thành công. Mời đăng nhập!')
            return redirect(url_for('login'))
        else:
            flash('❌ Tên đăng nhập đã tồn tại!')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        session_db = Session()
        user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=username).first()
        session_db.close()

        if user and check_password_hash(user.mat_khau, password):
            session['username'] = username
            flash('✅ Đăng nhập thành công!')
            return redirect(url_for('chat'))
        else:
            flash('❌ Sai tên đăng nhập hoặc mật khẩu!')
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))

    session_db = Session()
    all_users = session_db.query(TaiKhoan).filter(TaiKhoan.ten_dang_nhap != session['username']).all()
    session_db.close()
    return render_template('chat.html', username=session['username'], users=all_users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('🚪 Đã đăng xuất')
    return redirect(url_for('login'))

@app.route('/decrypt_des_key', methods=['POST'])
def decrypt_des_key():
    if 'username' not in session:
        return jsonify({'error': 'Chưa đăng nhập'}), 403

    data = request.get_json()
    enc_key_b64 = data.get("encrypted_des_key")
    if not enc_key_b64:
        return jsonify({'error': 'Thiếu encrypted_des_key'}), 400

    session_db = None
    try:
        print("🔐 Bắt đầu giải mã DES key")
        print("👤 Người dùng đang giải mã:", session['username'])

        # Fix base64 padding
        enc_key_b64 = enc_key_b64.replace(' ', '+')
        if len(enc_key_b64) % 4 != 0:
            enc_key_b64 += '=' * (4 - len(enc_key_b64) % 4)
        
        binary_encrypted = base64.b64decode(enc_key_b64)
        
        session_db = Session()
        user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=session['username']).first()
        
        # Kiểm tra tồn tại user và khóa
        if not user or not user.khoa or not user.khoa.khoa_ca_nhan:
            return jsonify({'error': 'Không tìm thấy khóa riêng tư'}), 404

        private_key = RSA.import_key(user.khoa.khoa_ca_nhan)
        
        # Sử dụng PKCS1_v1_5 thay vì OAEP để khớp với JSEncrypt
        cipher_rsa = PKCS1_v1_5.new(private_key)
        decrypted_bytes = cipher_rsa.decrypt(binary_encrypted, None)
        
        # Kiểm tra kết quả giải mã
        if not decrypted_bytes:
            raise ValueError("Giải mã trả về dữ liệu rỗng")

        decrypted_text = decrypted_bytes.decode('utf-8')

        print("✅ Giải mã DES key thành công")
        return jsonify({"des_data": decrypted_text})

    except Exception as e:
        print("❌ Lỗi giải mã DES key:", str(e))
        return jsonify({
            'error': 'Giải mã thất bại',
            'details': str(e),
            'debug_info': {
                'user_exists': bool(user),
                'has_key': bool(user and user.khoa),
                'key_length': len(user.khoa.khoa_ca_nhan) if user and user.khoa else 0,
                'input_length': len(enc_key_b64)
            }
        }), 500
    finally:
        if session_db:
            session_db.close()
def is_valid_key(key):
    try:
        RSA.import_key(key)
        return True
    except ValueError:
        return False
@app.route('/sign_info', methods=['POST'])
def sign_info():
    if 'username' not in session:
        return jsonify({'error': 'Chưa đăng nhập'}), 403

    data = request.get_json()
    info_str = json.dumps(data, sort_keys=True)
    h = SHA256.new(info_str.encode())

    session_db = Session()
    user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=session['username']).first()
    if not user or not user.khoa:
        session_db.close()
        return jsonify({'error': 'Không tìm thấy khóa riêng tư'}), 404

    private_key = RSA.import_key(user.khoa.khoa_ca_nhan)
    signature = pkcs1_15.new(private_key).sign(h)
    signature_b64 = base64.b64encode(signature).decode()

    session_db.close()
    return jsonify({'signature': signature_b64})

@app.route('/get_public_key')
def get_public_key():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Thiếu tên người dùng'}), 400

    session_db = Session()
    user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=username).first()
    if not user:
        session_db.close()
        return jsonify({'error': 'Không tìm thấy người dùng'}), 404

    khoa = session_db.query(Khoa).filter_by(ma_tai_khoan=user.ma_tai_khoan).first()
    if not khoa:
        session_db.close()
        return jsonify({'error': 'Không tìm thấy khóa của người dùng'}), 404

    session_db.close()
    return jsonify({'public_key': khoa.khoa_cong_khai})
@app.route('/check_key_pair')
def check_key_pair():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    session_db = Session()
    user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=session['username']).first()
    
    if not user or not user.khoa:
        return jsonify({'error': 'Key not found'}), 404
        
    try:
        # Test encryption/decryption
        private_key = RSA.import_key(user.khoa.khoa_ca_nhan)
        public_key = RSA.import_key(user.khoa.khoa_cong_khai)
        
        # Tạo cipher
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Mã hóa test message
        test_msg = b"Test123!"
        encrypted = cipher.encrypt(test_msg)
        
        # Giải mã
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        decrypted = cipher.decrypt(encrypted)
        
        return jsonify({
            'success': decrypted == test_msg,
            'key_match': '✅' if decrypted == test_msg else '❌'
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'private_key_start': user.khoa.khoa_ca_nhan[:50],
            'public_key_start': user.khoa.khoa_cong_khai[:50]
        }), 500
@app.route('/online_users')
def online_users():
    return jsonify({'users': list(clients.keys())})


@app.route('/debug_keys')
def debug_keys():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    session_db = Session()
    user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=session['username']).first()
    
    if not user or not user.khoa:
        return jsonify({'error': 'Không tìm thấy khóa'}), 404
    
    try:
        # Kiểm tra khóa riêng
        private_key = RSA.import_key(user.khoa.khoa_ca_nhan)
        # Kiểm tra khóa công khai
        public_key = RSA.import_key(user.khoa.khoa_cong_khai)
        
        return jsonify({
            'status': 'OK',
            'private_key_length': len(user.khoa.khoa_ca_nhan),
            'public_key_length': len(user.khoa.khoa_cong_khai),
            'key_matched': test_key_pair(public_key, private_key)
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'private_key_sample': user.khoa.khoa_ca_nhan[:100] + '...',
            'public_key_sample': user.khoa.khoa_cong_khai[:100] + '...'
        }), 500

def test_key_pair(public_key, private_key):
    """Kiểm tra cặp khóa có thể mã hóa/giải mã"""
    test_msg = b"Test message 123"
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted = cipher.encrypt(test_msg)
    
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(encrypted)
    return decrypted == test_msg
@app.route('/regenerate_keys', methods=['POST'])
def regenerate_keys():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    session_db = Session()
    user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=session['username']).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        # Tạo cặp khóa mới
        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        
        # Cập nhật database
        if not user.khoa:
            user.khoa = Khoa(
                khoa_cong_khai=public_key,
                khoa_ca_nhan=private_key
            )
        else:
            user.khoa.khoa_cong_khai = public_key
            user.khoa.khoa_ca_nhan = private_key
        
        session_db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@sock.route('/ws')
def websocket(ws):
    print(f"New WebSocket connection from {request.remote_addr}")
    username = None
    try:
        while True:
            data = ws.receive()
            if not data:
                break

            msg = json.loads(data)
            msg_type = msg.get("type")
            print(f"Received message type: {msg_type} from {username or 'unknown'}")

            if msg_type == "hello":
                username = msg.get("username")
                session_db = Session()
                user = session_db.query(TaiKhoan).filter_by(ten_dang_nhap=username).first()
                session_db.close()
                if not user:
                    ws.send(json.dumps({
                        "type": "error",
                        "message": f"❌ Tên người dùng {username} không tồn tại"
                    }))
                    ws.close()
                    break
                clients[username] = ws
                ws.send(json.dumps({
                    "type": "ready",
                    "message": f"✅ Server sẵn sàng cho {username}"
                }))
                print(f"Registered user: {username}")

            elif msg_type == "public_key":
                print(f"🔐 Nhận public key từ {username}")

            elif msg_type in ["key_exchange", "message", "ack", "nack"]:
                to_user = msg.get("to")
                if to_user in clients:
                    clients[to_user].send(json.dumps(msg))
                    print(f"Forwarded message to {to_user}")
                else:
                    print(f"⚠️ Người dùng {to_user} không online.")
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
    finally:
        if username in clients:
            del clients[username]
            print(f"Disconnected user: {username}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
print(f"Encrypted data length: {len(binary_encrypted)}")
print(f"Encrypted data hex: {binary_encrypted.hex()[:50]}...")