Đề tài: Ứng dụng bảo mật tin nhắn văn bản với mã hoá DES và xác thực RSA
Mô tả
Một hệ thống bảo mật cho ứng dụng nhắn tin văn bản, nơi nội dung tin nhắn được mã hóa bằng DES để đảm bảo bí
mật, trong khi danh tính người gửi và người nhận được xác thực bằng RSA. Hệ thống sử dụng hàm băm SHA-256 để
kiểm tra tính toàn vẹn của thông điệp, giúp ngăn chặn việc giả mạo hoặc thay đổi dữ liệu trong quá trình truyền tải.
Yêu cầu
• Mã hóa: DES (CFB mode)
• Trao khóa & ký số: RSA 2048-bit (OAEP + SHA-256)
• Kiểm tra tính toàn vẹn: SHA-256
Luồng xử lý
1. Handshake
• Người gửi gửi "Hello!"
• Người nhận trả lời "Ready!"
• Hai bên trao đổi khóa công khai RSA qua kết nối P2P
2. Xác thực & Trao khóa
• Người gửi ký ID bằng RSA/SHA-256
• Người gửi tạo khóa DES và mã hóa nó bằng RSA công khai của người nhận
• Gửi:
{
"signed_info": "<RSA Signature>",
"encrypted_des_key": "<Base64>"
}
3. Mã hóa & Kiểm tra toàn vẹn
• Tin nhắn văn bản được mã hóa bằng DES
• Tạo hash: SHA-256(ciphertext)
4. Phía Người nhận
• Giải mã khóa DES bằng RSA
• Kiểm tra tính toàn vẹn của ciphertext bằng SHA-256
• Xác thực chữ ký RSA
• Nếu hợp lệ:
– Giải mã nội dung tin nhắn bằng DES
– Hiển thị tin nhắn văn bản
– Gửi ACK xác nhận
• Nếu không hợp lệ:
– Gửi NACK với lý do: lỗi hash hoặc chữ ký


5. Luồng sự kiện tổng thể của hệ thống

![image](https://github.com/user-attachments/assets/09872148-ede7-418e-aa93-04eaa3c96bdb)

Sơ đồ luồng sự kiện đăng ký

![image](https://github.com/user-attachments/assets/ab6c5e6e-e824-4d6a-8fe4-403d7a2d748e)

Sơ đồ luồng sự kiện đăng nhập

![image](https://github.com/user-attachments/assets/6833815e-0dcf-49bd-aff3-59f3f4d88cba)

Sơ đồ luồng sự kiện trao đổi khóa (Handshake)

![image](https://github.com/user-attachments/assets/79fecd9c-41d3-46d6-82db-13c42cb64fe1)

Sơ đồ luồng sự kiện gửi tin nhắn

![image](https://github.com/user-attachments/assets/37393984-cc78-41d4-978f-09d1870f43af)

Sơ đồ luồng sự kiện nhận tin nhắn

![image](https://github.com/user-attachments/assets/fd4e932e-7322-47ea-ba42-8425b8fb3c88)

Giao diện đăng ký

![image](https://github.com/user-attachments/assets/5d5b6577-ea4d-4681-aa71-94644427f9f7)

Giao diện đăng nhập

![image](https://github.com/user-attachments/assets/a8852764-419a-437c-a18c-7210ee5b932d)

Giao diện chat

![image](https://github.com/user-attachments/assets/63a7d9e4-342b-4062-b651-5f6951f386eb)

6. Mô phỏng truyền dữ liệu

Khi người dùng đăng nhập thành công hệ thống sẽ lấy thông tin của người dùng trong database.
 

![image](https://github.com/user-attachments/assets/4f660963-74d6-4139-9370-5af3622c6ae3)

- Người dùng A bấm vào người dùng B để nhắn tin hệ thống sẽ tạo mã DES key và gửi sang bên còn lại khi bên B nhấn vào bên A thì sẽ nhận được khóa DES key đã được mã hóa và public key của A đồng thời bên A cũng nhận đc public key của B.

![image](https://github.com/user-attachments/assets/c0e9eb99-42f1-4ba9-aed2-1a507f2d89dd)

- Khi 1 bên gửi tin nhắn hệ thống sẽ mã hóa và gửi đến bên còn lại.

![image](https://github.com/user-attachments/assets/9752df67-d02e-4e70-b31c-df67c10e662f)


