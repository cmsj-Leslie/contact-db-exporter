"""
第一步：从微信进程内存中提取数据库密钥
================================================

原理简述：
  微信运行时必须解密本地数据库，所以解密密钥一定在进程内存里。
  微信把它以 x'<64位十六进制>' 的文本格式存放，本脚本扫描内存
  匹配这个格式，再用数据库第一页做 HMAC 校验确认是真密钥。

使用方法：
  1. 先改好 config.py 里的 DB_DIR
  2. 保持微信登录运行
  3. 以【管理员身份】运行：python extract_key.py
  4. 成功后密钥会打印在终端，并保存到 输出目录/key.txt

注意：必须管理员身份运行，否则无法读取微信进程内存。
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess

import config
from crypto_utils import verify_enc_key, read_db_page1, PAGE_SZ, SALT_SZ

# 让 print 实时输出，不被缓冲（方便看进度）
import functools
print = functools.partial(print, flush=True)

# ── Windows 内存 API 相关常量 ───────────────────────────────
kernel32 = ctypes.windll.kernel32
MEM_COMMIT = 0x1000  # 已提交的内存（真正分配了物理/页面文件的内存）
# 可读的内存保护标志集合（只读、读写、写时复制、可执行可读等）
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
# OpenProcess 权限：PROCESS_VM_READ(0x10) | PROCESS_QUERY_INFORMATION(0x400)
PROCESS_ACCESS = 0x0010 | 0x0400


class MBI(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION 结构体（64 位布局）。

    VirtualQueryEx 通过它返回某块内存区域的基址、大小、状态、保护属性。
    _pad1 / _pad2 是 64 位下的对齐填充，必须保留，否则字段会错位。
    """
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def get_pids():
    """找到所有微信进程，按内存占用从大到小排序。

    主进程内存占用最大，密钥通常在主进程里，所以优先扫描。
    返回 [(pid, 内存KB), ...]
    """
    r = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {config.WECHAT_PROCESS}", "/FO", "CSV", "/NH"],
        capture_output=True, text=True
    )
    pids = []
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        # CSV 格式："映像名","PID","会话名","会话#","内存使用"
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(',', '').replace(' K', '').strip() or '0')
            pids.append((pid, mem))
    if not pids:
        raise RuntimeError(f"{config.WECHAT_PROCESS} 未运行，请先登录微信")
    pids.sort(key=lambda x: x[1], reverse=True)
    return pids


def read_mem(h, addr, sz):
    """从进程句柄 h 的 addr 地址读取 sz 字节，失败返回 None。"""
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def enum_regions(h):
    """枚举进程所有【已提交且可读】的内存区域。

    跳过超大块（>500MB），避免单次读取过慢。
    返回 [(基址, 大小), ...]
    """
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:  # 防止地址回绕导致死循环
            break
        addr = nxt
    return regs


def find_key(contact_db):
    """扫描微信内存，找到能通过 HMAC 校验的真密钥。找不到返回 None。"""
    page1 = read_db_page1(contact_db)
    salt_hex = page1[:SALT_SZ].hex()
    print(f"contact.db salt: {salt_hex}")

    # 微信内存里密钥的两种长度：
    #   64 位 = 纯密钥（salt 单独从数据库文件头读）
    #   96 位 = 密钥(64) + salt(32) 拼在一起
    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")

    for pid, mem_kb in get_pids():
        print(f"扫描进程 PID={pid} ({mem_kb // 1024}MB)...")
        h = kernel32.OpenProcess(PROCESS_ACCESS, False, pid)
        if not h:
            print("  打不开进程，跳过（请确认以管理员身份运行）")
            continue
        try:
            for base, size in enum_regions(h):
                data = read_mem(h, base, size)
                if not data:
                    continue
                for m in hex_re.finditer(data):
                    hex_str = m.group(1).decode()
                    if len(hex_str) == 96:
                        enc_key_hex, s = hex_str[:64], hex_str[64:]
                    elif len(hex_str) == 64:
                        enc_key_hex, s = hex_str, salt_hex
                    else:
                        continue
                    if s != salt_hex:
                        continue
                    # 用候选密钥对第一页做 HMAC 校验，通过才是真密钥
                    if verify_enc_key(bytes.fromhex(enc_key_hex), page1):
                        print(f"  [找到密钥] {enc_key_hex}")
                        return enc_key_hex
        finally:
            kernel32.CloseHandle(h)
    return None


def main():
    print("=" * 50)
    print("微信数据库密钥提取")
    print("=" * 50)

    db_dir = config.DB_DIR
    contact_db = os.path.join(db_dir, "contact", "contact.db")
    if not os.path.exists(contact_db):
        print(f"\n找不到 contact.db：{contact_db}")
        print("请检查 config.py 里的 DB_DIR 是否正确")
        return

    key = find_key(contact_db)
    if not key:
        print("\n未找到密钥。请确认：微信已登录运行，且本脚本以管理员身份运行。")
        return

    # 保存到 输出目录/key.txt
    out_dir = config.OUTPUT_DIR if os.path.isabs(config.OUTPUT_DIR) \
        else os.path.join(os.path.dirname(os.path.abspath(__file__)), config.OUTPUT_DIR)
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, "key.txt")
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(f"db_dir: {db_dir}\n")
        f.write(f"enc_key: {key}\n")
        # 下面这行可直接粘贴到 DB Browser for SQLite (SQLCipher) 打开加密库
        f.write(f"PRAGMA key=\"x'{key}'\";\n")
    print(f"\n密钥已保存到：{key_path}")
    print("下一步：运行 python export_contacts.py 解密并导出联系人")


if __name__ == "__main__":
    main()
