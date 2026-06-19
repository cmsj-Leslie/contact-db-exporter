"""
SQLCipher 解密与校验的公共函数
================================================

extract_key.py（提取密钥）和 export_contacts.py（解密导出）都用到这里的函数。
微信数据库用 SQLCipher 4 加密，核心参数如下，一般不需要改动。
"""
import hashlib
import hmac as hmac_mod
import struct

from Crypto.Cipher import AES

# ── SQLCipher 4 页面参数 ────────────────────────────────────
PAGE_SZ = 4096    # 每页字节数
SALT_SZ = 16      # 文件头明文 salt 长度
IV_SZ = 16        # AES-CBC 初始向量长度
HMAC_SZ = 64      # HMAC-SHA512 输出长度
RESERVE_SZ = 80   # 每页末尾保留区长度（IV + HMAC + 填充）
SQLITE_HDR = b'SQLite format 3\x00'  # 标准 SQLite 文件魔数头


def read_db_page1(db_path):
    """读取数据库第一页（4096 字节）。第一页头部含 salt 和 HMAC，用于校验。"""
    with open(db_path, "rb") as f:
        return f.read(PAGE_SZ)


def derive_mac_key(enc_key, salt):
    """从密钥和 salt 派生出用于 HMAC 校验的 mac_key。

    SQLCipher 规则：mac_salt = salt 每字节 XOR 0x3A，
    再用 PBKDF2-SHA512 迭代 2 次派生 32 字节。
    """
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=32)


def verify_enc_key(enc_key, page1):
    """用候选密钥对第一页做 HMAC-SHA512 校验，判断密钥是否正确。

    校验数据范围 page1[16 : 4032]（去掉头部 salt，保留到含 IV）、
    末尾再拼上小端页号 1，算出的 HMAC 应等于 page1 最后 64 字节。
    """
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    hmac_data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored_hmac = page1[PAGE_SZ - HMAC_SZ: PAGE_SZ]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))  # 页号 1，小端 4 字节
    return hm.digest() == stored_hmac


def decrypt_page(enc_key, page_data, pgno):
    """解密单个数据库页。

    - enc_key：32 字节密钥
    - page_data：该页原始加密数据（4096 字节）
    - pgno：页号，从 1 开始（第 1 页需特殊处理）

    说明：标准 SQLCipher 流程里，AES 密钥是“用户密码 + salt 经 PBKDF2-SHA512
    迭代 64000 次”派生出来的。但本工具从微信内存里取到的 enc_key，已经是
    这一派生【之后】的最终 256 位密钥，所以这里直接拿它当 AES key 用，
    无需再做 PBKDF2。（README“数据库解密”一节描述的是 SQLCipher 的完整原理，
    而内存取密钥这条路径恰好跳过了派生步骤。）
    """
    # 每页 IV 在末尾保留区的前 16 字节
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    if pgno == 1:
        # 第 1 页：跳过头部 16 字节 salt 再解密，解出后补回 SQLite 魔数头
        decrypted = cipher.decrypt(page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ])
        return SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ
    else:
        # 其他页：整页内容（去掉末尾保留区）全部解密
        decrypted = cipher.decrypt(page_data[:PAGE_SZ - RESERVE_SZ])
        return decrypted + b'\x00' * RESERVE_SZ


def decrypt_db(db_path, out_path, enc_key_hex):
    """逐页解密整个数据库文件，输出标准 SQLite 文件。成功返回 True。"""
    enc_key = bytes.fromhex(enc_key_hex)
    page1 = read_db_page1(db_path)

    # 先校验密钥，避免用错钥匙解出一堆乱码
    if not verify_enc_key(enc_key, page1):
        print("HMAC 校验失败：密钥不正确，或数据库与该密钥不匹配")
        return False
    print("HMAC 校验通过，开始解密...")

    import os
    total_pages = os.path.getsize(db_path) // PAGE_SZ
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if not page:
                break
            fout.write(decrypt_page(enc_key, page, pgno))
    print(f"解密完成：{out_path}")
    return True
