import os
import sys

title_flags = {
    "JPG": b"\xff\xd8\xff",
    "PNG": b"\x89\x50\x4e\x47",
    "BMP": b"\x42\x4d",
    "GIF": b"\x47\x49\x46\x38",
    "ZIP": b"\x50\x4b\x03\x04",
    "RAR": b"\x52\x61\x72\x21",
    "AVI": b"\x41\x56\x49\x20"
}

def get_file_extension(header_bytes):
    """根据文件头字节返回文件扩展名"""
    for file_type, signature in title_flags.items():
        if header_bytes.startswith(signature):
            return file_type.lower()  # 返回小写格式的扩展名
    return None

def image_decode(in_path, out_path):
    """
    解密dat文件
    param:
        in_path: 输入文件路径 + 文件名
        out_path: 输出路径 + 输入文件名
    ret:
        None
    """
    with open(in_path, "rb") as dat_read:
        # 读取文件内容
        content = dat_read.read()

    # 获取前2字节以判断文件类型
    file_flag = int.from_bytes(content[0:2], byteorder="big", signed=False)
    xor_flag = None  # 将用于 XOR 的值初始化为 None
    decoded_bytes = bytearray()  # 用于存储解码后的字节内容

    # 首先遍历内容来获取 XOR 标志
    for index, nowByte in enumerate(content):
        if index == 0:  # 第一次读取数据
            for k in title_flags.keys():
                t_f = title_flags[k][0:2]
                t_f = int.from_bytes(t_f, byteorder="big", signed=False)
                f_type0 = t_f ^ file_flag
                f_type = hex(f_type0)
                f_type1 = f_type[2:4]
                f_type2 = f_type[4:6]
                if f_type1 == f_type2:
                    xor_flag = f_type0 % 256  # 取出f_type0的后两位，用于xor
            if xor_flag is None:
                raise ValueError("Unsupported file type")

        # 进行 XOR 操作
        newByte = nowByte ^ xor_flag
        decoded_bytes.append(newByte)

    # 现在检查解码后的字节，获取文件类型
    decoded_content = bytes(decoded_bytes)
    max_signature_length = max(len(sig) for sig in title_flags.values())  # 获取最大签名长度
    file_extension = get_file_extension(decoded_content[:max_signature_length])  # 修复括号问题

    if file_extension is None:
        raise ValueError("Unsupported file type after decoding")

    out_file = f"{out_path}.{file_extension}"  # 设置输出文件名
    
    # 写入解码后的文件
    with open(out_file, "wb") as output_file:
        output_file.write(decoded_content)

def main():
    if len(sys.argv) != 2:
        sys.exit(f'{sys.argv[0]} keli.dat')
    in_path = sys.argv[1]
    file_name = os.path.basename(in_path)
    out_path = os.path.splitext(file_name)[0]  # 只取文件名，去掉扩展名
    image_decode(in_path, out_path)

if __name__ == "__main__":
    main()
