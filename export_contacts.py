"""
第二步：解密 contact.db 并导出联系人列表到 CSV
================================================

使用方法：
  1. 先跑过 extract_key.py（或在 config.py 里手填 ENC_KEY_HEX）
  2. 运行：python export_contacts.py
  3. 结果输出到 config.py 的 OUTPUT_DIR 目录，一次生成两份 CSV：
     - contacts.csv            全量：全部联系人 + 全部原始字段（英文表头）
     - <账号名>的好友列表.csv   精简：仅真实好友 + 中文表头 + 手机号
     另外还有中间产物 contact_dec.db（解密后的标准 SQLite 库，可用 DB Browser 打开）

  其中 <账号名> 取自 config.py 的 ACCOUNT_NAME。
"""
import csv
import os
import re
import sqlite3

import config
from crypto_utils import decrypt_db

# —— 精简版（好友列表）用：隐藏字段 + 中文表头 ——
# 这些字段对人没意义（内部 id、拼音索引、头像 URL、二进制 buffer 等），精简版不输出
HIDDEN_COLS = {
    'id', 'delete_flag', 'verify_flag', 'encrypt_username',
    'extra_buffer', 'head_img_md5', 'remark_quan_pin',
    'remark_pin_yin_initial', 'pin_yin_initial', 'quan_pin',
    'big_head_url', 'small_head_url', 'chat_room_notify',
    'is_in_chat_room', 'description', 'chat_room_type', 'flag',
}

# 数据库英文字段名 → CSV 中文表头（仅精简版用）
COL_NAMES = {
    'username':   '微信号',
    'local_type': '类型',
    'alias':      '微信号别名',
    'remark':     '备注名',
    'nick_name':  '昵称',
}


def resolve_output_dir():
    """把 config.OUTPUT_DIR 解析成绝对路径（"." = 脚本所在目录）。"""
    if os.path.isabs(config.OUTPUT_DIR):
        return config.OUTPUT_DIR
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), config.OUTPUT_DIR)


def get_enc_key(out_dir):
    """获取密钥：优先用 config.ENC_KEY_HEX，否则从 out_dir/key.txt 读。"""
    if config.ENC_KEY_HEX.strip():
        return config.ENC_KEY_HEX.strip()
    key_path = os.path.join(out_dir, "key.txt")
    if os.path.exists(key_path):
        with open(key_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("enc_key:"):
                    return line.split(":", 1)[1].strip()
    return ""


def extract_phone(buf):
    """从 extra_buffer 二进制里正则匹配中国大陆手机号（部分好友有）。"""
    if not buf:
        return ''
    phones = re.findall(rb'1[3-9]\d{9}', buf)
    return phones[0].decode() if phones else ''


def export_full(conn, cols, csv_path):
    """全量版：全部联系人（不过滤）+ 全部原始字段，英文表头。

    二进制字段（如 extra_buffer）用 Python repr 形式输出，避免破坏 CSV。
    """
    rows = conn.execute("SELECT * FROM contact").fetchall()
    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        for row in rows:
            writer.writerow([
                '' if v is None else (repr(v) if isinstance(v, bytes) else v)
                for v in row
            ])
    print(f"全量联系人：{len(rows)} 条 → {csv_path}")


def export_friends(conn, cols, csv_path):
    """精简版：仅真实好友（local_type=1），中文表头 + 手机号。"""
    # local_type=1 是普通好友；2=群聊 3=公众号 0/5=系统账号
    rows = conn.execute("SELECT * FROM contact WHERE local_type = 1").fetchall()
    extra_idx = cols.index('extra_buffer')
    visible_idx = [i for i, c in enumerate(cols) if c not in HIDDEN_COLS]
    header = ['序号'] + [COL_NAMES.get(cols[i], cols[i]) for i in visible_idx] + ['手机号']

    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for idx, row in enumerate(rows, start=1):
            phone = extract_phone(row[extra_idx])
            writer.writerow([idx] + [row[i] for i in visible_idx] + [phone])

    phone_count = sum(1 for r in rows if extract_phone(r[extra_idx]))
    print(f"真实好友：{len(rows)} 条（其中 {phone_count} 条含手机号）→ {csv_path}")


def main():
    print("=" * 50)
    print("微信联系人解密导出")
    print("=" * 50)

    contact_db = os.path.join(config.DB_DIR, "contact", "contact.db")
    if not os.path.exists(contact_db):
        print(f"找不到 contact.db：{contact_db}\n请检查 config.py 的 DB_DIR")
        return

    out_dir = resolve_output_dir()
    os.makedirs(out_dir, exist_ok=True)

    key = get_enc_key(out_dir)
    if not key:
        print("没有可用密钥。请先运行 extract_key.py，或在 config.py 填 ENC_KEY_HEX")
        return

    out_db = os.path.join(out_dir, "contact_dec.db")
    if not decrypt_db(contact_db, out_db, key):
        return

    # 解密成功后，一次生成两份 CSV
    full_csv = os.path.join(out_dir, "contacts.csv")
    friends_csv = os.path.join(out_dir, f"{config.ACCOUNT_NAME}的好友列表.csv")

    conn = sqlite3.connect(out_db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(contact)").fetchall()]
    export_full(conn, cols, full_csv)
    export_friends(conn, cols, friends_csv)
    conn.close()
    print("=" * 50)


if __name__ == "__main__":
    main()
