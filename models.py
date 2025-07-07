from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from werkzeug.security import generate_password_hash
from Crypto.PublicKey import RSA

Base = declarative_base()

def get_engine():
    return create_engine('sqlite:///database.db', echo=False)

# Tạo database và các bảng
def create_db():
    engine = get_engine()
    Base.metadata.create_all(engine)
    print("✅ Đã tạo database và các bảng.")

class TaiKhoan(Base):
    __tablename__ = 'tai_khoan'

    ma_tai_khoan = Column(Integer, primary_key=True, autoincrement=True)
    ten_dang_nhap = Column(String(50), unique=True, nullable=False)
    mat_khau = Column(String(256), nullable=False)

    nguoi_dung = relationship("NguoiDung", back_populates="tai_khoan", uselist=False)
    khoa = relationship("Khoa", back_populates="tai_khoan", uselist=False)

class NguoiDung(Base):
    __tablename__ = 'nguoi_dung'

    ma_nguoi_dung = Column(Integer, primary_key=True, autoincrement=True)
    ten_nguoi_dung = Column(String(100), nullable=False)
    ma_tai_khoan = Column(Integer, ForeignKey('tai_khoan.ma_tai_khoan'))

    tai_khoan = relationship("TaiKhoan", back_populates="nguoi_dung")

class Khoa(Base):
    __tablename__ = 'khoa'

    ma_khoa = Column(Integer, primary_key=True, autoincrement=True)
    khoa_cong_khai = Column(String, nullable=False)
    khoa_ca_nhan = Column(String, nullable=False)
    ma_tai_khoan = Column(Integer, ForeignKey('tai_khoan.ma_tai_khoan'))

    tai_khoan = relationship("TaiKhoan", back_populates="khoa")

# Hàm đăng ký người dùng kèm tạo RSA key pair
def register_user(ten_dang_nhap, mat_khau, ten_nguoi_dung):
    # Đảm bảo các bảng đã được tạo
    create_db()

    engine = get_engine()
    Session = sessionmaker(bind=engine)
    session = Session()

    # Kiểm tra tồn tại username
    if session.query(TaiKhoan).filter_by(ten_dang_nhap=ten_dang_nhap).first():
        print("❌ Tên đăng nhập đã tồn tại.")
        return False

    # Hash mật khẩu
    hashed_password = generate_password_hash(mat_khau)

    # Tạo tài khoản
    tai_khoan = TaiKhoan(
        ten_dang_nhap=ten_dang_nhap,
        mat_khau=hashed_password
    )
    session.add(tai_khoan)
    session.commit()  # commit để có ma_tai_khoan

    # Thêm người dùng
    nguoi_dung = NguoiDung(
        ten_nguoi_dung=ten_nguoi_dung,
        ma_tai_khoan=tai_khoan.ma_tai_khoan
    )
    session.add(nguoi_dung)

    # Tạo RSA key pair
    rsa_key = RSA.generate(2048)
    private_key_pem = rsa_key.export_key().decode()
    public_key_pem = rsa_key.publickey().export_key().decode()

    khoa = Khoa(
        khoa_cong_khai=public_key_pem,
        khoa_ca_nhan=private_key_pem,
        ma_tai_khoan=tai_khoan.ma_tai_khoan
    )
    session.add(khoa)

    session.commit()
    print("✅ Đăng ký thành công và đã tạo khóa RSA.")
    return True

if __name__ == '__main__':
    create_db()
