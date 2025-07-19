# !/usr/bin/env python
# -*- coding:utf-8 -*-

# @Author :随波逐流
# @Name :随曰文本加解密工具
# @Version :V1.0
# @Vertime :20250718

'''
随曰SuiYue:https://github.com/zb848/suiyue-crypto
'''

from __future__ import unicode_literals
import base64
import hashlib
import hmac
import os
from Crypto.Cipher import AES, ChaCha20_Poly1305
import zlib

# ---------- 常量 ----------
PBKDF2_ITERATIONS = 500000
HKDF_HASH_FUNCTION = hashlib.sha256
AES_BLOCK_SIZE = 16  # AES块大小为16字节
AES_COUNTER_LENGTH = 8  # 计数器长度为8字节(64位)

DEFAULT_PASSWORD = "39d68eef8be0f55de9916b927ed50b9c64994f4ab595aef03c5feaaed84d27b5" # 默认密码

# ---------- 辅助函数 ----------
def convert_to_bytes(text):
    """将字符串转换为UTF-8字节"""
    if isinstance(text, str):
        return text.encode('utf-8')
    return text


def string_to_bytearray(text):
    """将字符串转换为UTF-8字节数组"""
    return bytearray(convert_to_bytes(text))


def bytearray_to_string(byte_array):
    """将字节数组转换为UTF-8字符串"""
    return bytes(byte_array).decode('utf-8')


def base64url_decode(data):
    """去掉补全符号的base64url解码"""
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return base64.urlsafe_b64decode(convert_to_bytes(data))


# ---------- 中文-Base64 映射 ----------
CHARACTER_SETS={
 'A': ['濈', '澙', '涍', '湺', '澵', '泗', '浐', '激', '湜', '灜', '涧', '澨', '澕', '澰'],
 'B': ['漋', '潍', '沸', '洪', '漌', '溥', '湛', '渗', '里', '滁', '淜', '沭', '渼', '滋'],
 'C': ['浙', '浑', '潞', '汹', '澉', '泚', '滶', '汻', '洣', '澦', '瀂', '瀩', '澡', '濚'],
 'D': ['濔', '濝', '渁', '瀤', '漍', '濭', '瀗', '潻', '泖', '淏', '灦', '潉', '汾', '溙'],
 'E': ['渔', '况', '汊', '澎', '漺', '浽', '泜', '浈', '沼', '濄', '涉', '灟', '灆', '涜'],
 'F': ['滵', '淸', '沘', '汒', '潩', '洲', '汰', '湑', '澋', '湳', '澅', '涴', '涣', '澺'],
 'G': ['淋', '滙', '洽', '淑', '淝', '泞', '潢', '溵', '泮', '浚', '淤', '澶', '沟', '浕'],
 'H': ['淳', '洅', '瀞', '清', '溠', '沠', '瀚', '泎', '滊', '潦', '湈', '流', '洭', '潨'],
 'I': ['漙', '渮', '濥', '沙', '淉', '洷', '渘', '漩', '涁', '演', '济', '濋', '涘', '澐'],
 'J': ['洝', '湙', '濜', '澛', '浺', '澯', '淐', '渋', '灢', '溁', '湦', '汲', '浥', '渃'],
 'K': ['滦', '湾', '灅', '濹', '瀇', '濡', '沞', '渑', '灔', '汭', '沕', '澢', '泀', '泃'],
 'L': ['淃', '漯', '濣', '池', '漱', '浿', '深', '浟', '淖', '泌', '涌', '濨', '汉', '溍'],
 'M': ['泑', '瀊', '湎', '湍', '汯', '湿', '溡', '渢', '渀', '泪', '漄', '涭', '溹', '涡'],
 'N': ['漛', '湇', '涢', '湡', '沎', '渫', '潧', '渪', '溔', '潹', '澬', '漹', '沰', '漂'],
 'O': ['洧', '湀', '滞', '湤', '滒', '滀', '瀡', '泒', '潺', '瀸', '瀯', '浼', '淊', '沵'],
 'P': ['溿', '渷', '浸', '溎', '洇', '濓', '溞', '瀙', '滱', '淧', '法', '涱', '减', '澷'],
 'Q': ['潬', '洤', '灏', '涚', '汘', '浒', '濳', '灖', '浫', '氿', '淔', '洆', '洂', '涂'],
 'R': ['汦', '湥', '滰', '涯', '渲', '汕', '沆', '漻', '渿', '氻', '沶', '沅', '泿', '温'],
 'S': ['洴', '湭', '溲', '潐', '淯', '溻', '汃', '淹', '浵', '漭', '浭', '滂', '滹', '涹'],
 'T': ['涬', '淗', '洀', '潜', '汅', '澄', '溤', '淬', '溂', '浴', '湸', '灂', '溧', '滃'],
 'U': ['汷', '渨', '沐', '涞', '濲', '冱', '灨', '漎', '澟', '灈', '漊', '濏', '涖', '浢'],
 'V': ['洉', '涒', '渒', '溷', '渠', '泯', '湃', '滪', '潎', '沋', '潭', '浨', '濻', '淦'],
 'W': ['澻', '淇', '溯', '泡', '瀓', '涑', '濆', '灚', '潅', '沧', '淢', '泇', '浅', '澿'],
 'X': ['潇', '溶', '瀳', '潣', '澝', '湁', '濙', '沇', '瀀', '湲', '瀭', '渐', '涀', '澓'],
 'Y': ['溢', '潪', '闵', '瀮', '决', '泟', '淁', '泦', '涕', '澔', '涛', '湘', '濠', '沬'],
 'Z': ['溽', '渟', '漗', '淿', '瀬', '湢', '瀥', '漜', '灍', '潓', '泐', '沪', '消', '混'],
 'a': ['沽', '滏', '溊', '泥', '漧', '注', '沿', '濽', '涓', '瀖', '洙', '洎', '湹', '溉'],
 'b': ['滍', '沂', '濒', '澳', '汧', '漈', '洒', '汌', '濎', '潕', '淰', '濂', '漥', '沌'],
 'c': ['涫', '濶', '滔', '溬', '洄', '渵', '泩', '潈', '渰', '漞', '泤', '沦', '湮', '滐'],
 'd': ['湂', '沾', '渡', '湉', '澣', '滟', '浔', '浝', '漷', '浛', '瀜', '溪', '净', '滢'],
 'e': ['湚', '潾', '涤', '洱', '浤', '泭', '澌', '瀔', '洐', '滼', '漪', '滭', '涻', '溴'],
 'f': ['涷', '淎', '濊', '溨', '漮', '渎', '渌', '湄', '澑', '潃', '澊', '滉', '沔', '汶'],
 'g': ['漑', '瀈', '沢', '渱', '滘', '汓', '溋', '渖', '泍', '漡', '瀼', '洿', '漓', '淩'],
 'h': ['汤', '渶', '澧', '滆', '洍', '凉', '渏', '瀛', '澁', '润', '泠', '洓', '漤', '洺'],
 'i': ['渄', '洼', '渇', '洰', '沉', '滽', '渽', '浖', '浳', '潌', '澽', '泾', '灛', '潶'],
 'j': ['澹', '湠', '泸', '湆', '潠', '泺', '淫', '汜', '汋', '浗', '濵', '漰', '洵', '浠'],
 'k': ['汈', '泧', '濇', '泈', '洖', '溜', '湽', '湏', '潝', '渂', '濍', '渍', '浩', '滗'],
 'l': ['湋', '瀴', '澾', '漖', '浀', '澲', '汫', '滖', '涄', '滧', '汑', '湐', '渻', '澈'],
 'm': ['泽', '洗', '漝', '涸', '汢', '瀱', '漫', '漴', '滝', '滫', '濞', '洫', '泓', '濅'],
 'n': ['湔', '溇', '濉', '瀒', '涎', '浍', '汄', '浘', '汝', '汀', '澞', '漶', '灋', '満'],
 'o': ['洦', '洳', '潮', '浏', '洏', '澚', '瀎', '涰', '濢', '洊', '洸', '沨', '潳', '活'],
 'p': ['涔', '泅', '漼', '漉', '沲', '洕', '沈', '沱', '灌', '澥', '潟', '潥', '测', '冲'],
 'q': ['灡', '沃', '涅', '汐', '淴', '涏', '澸', '瀿', '潫', '湨', '溑', '沛', '淌', '澭'],
 'r': ['浡', '涟', '汩', '溳', '滣', '游', '濛', '渓', '溓', '湴', '浦', '瀑', '漠', '洠'],
 's': ['潸', '泔', '溗', '滠', '濯', '滤', '灞', '洌', '沜', '渚', '浪', '渭', '淅', '灊'],
 't': ['涃', '洃', '漅', '溸', '澖', '溛', '灀', '渤', '濖', '源', '湅', '满', '漘', '瀻'],
 'u': ['濐', '洈', '溚', '滩', '洑', '湟', '浃', '潱', '沏', '瀺', '澼', '漆', '湼', '渣'],
 'v': ['泄', '潀', '滴', '灎', '泲', '瀃', '洨', '涗', '泻', '浉', '澏', '瀐', '滻', '洹'],
 'w': ['泳', '涆', '泂', '涩', '涳', '淂', '浧', '泋', '潡', '浯', '湒', '滇', '灠', '渥'],
 'x': ['瀹', '潗', '淞', '泷', '渴', '淆', '泱', '泼', '濦', '汪', '沩', '渳', '淈', '溩'],
 'y': ['溕', '湫', '涐', '油', '渉', '湪', '涶', '滨', '涠', '澪', '淠', '淟', '潲', '漳'],
 'z': ['汮', '湩', '沫', '淣', '没', '潂', '涺', '浇', '淕', '洞', '渹', '洔', '洋', '浓'],
 '0': ['洁', '淓', '洢', '淀', '洚', '泬', '溱', '潄', '沺', '溟', '滥', '浊', '泙', '淘'],
 '1': ['瀣', '湷', '濪', '洮', '津', '派', '滈', '溭', '潋', '灗', '沁', '涮', '濸', '滑'],
 '2': ['汽', '浰', '濩', '涪', '溣', '潖', '潽', '洡', '沷', '沄', '沥', '湝', '溰', '浾'],
 '3': ['溃', '汚', '渝', '潏', '浲', '灇', '湻', '瀵', '灉', '滓', '溦', '汵', '漾', '治'],
 '4': ['瀌', '瀶', '涿', '濮', '浣', '浮', '渺', '泛', '渧', '瀢', '灐', '汿', '涨', '浞'],
 '5': ['濴', '湌', '漽', '済', '沴', '渊', '湓', '汸', '溆', '浜', '泫', '潆', '涾', '漕'],
 '6': ['濗', '瀍', '淍', '泣', '浄', '淽', '滮', '溘', '灙', '溏', '添', '湗', '涊', '沮'],
 '7': ['瀫', '氾', '滺', '汱', '泏', '汔', '淮', '湕', '濿', '澴', '潵', '滚', '浱', '潼'],
 '8': ['洛', '澜', '漏', '浂', '泊', '泹', '汼', '滛', '汛', '潚', '浶', '濧', '澒', '泘'],
 '9': ['湶', '污', '涝', '渞', '凑', '沣', '湰', '漃', '灧', '凄', '涽', '瀷', '澘', '汳'],
 '+': ['汥', '涵', '沤', '淲', '滳', '湵', '涥', '淛', '漟', '溺', '潊', '浻', '泆', '洬'],
 '/': ['汁', '灁', '汏', '滜', '淄', '溅', '浌', '洘', '漇', '汣', '潘', '瀽', '潴', '溮'],
 '=': ['沚', '港', '濑', '澍', '灒', '汇', '淡', '汴', '潒', '淙', '液', '澫', '溒', '漨']
}

# 反向映射
CHINESE_TO_BASE64_MAP = {}
for base64_char, chinese_characters in CHARACTER_SETS.items():
    for chinese_char in chinese_characters:
        CHINESE_TO_BASE64_MAP[chinese_char] = base64_char


def chinese_to_base64(chinese_text):
    """将中文编码的Base64转换为标准Base64"""
    output = []
    for char in chinese_text:
        output.append(CHINESE_TO_BASE64_MAP.get(char, char))
    return ''.join(output)


def base64_to_chinese(base64_text):
    """将标准Base64转换为中文编码的Base64"""
    output = []
    for char in base64_text:
        if char in CHARACTER_SETS:
            output.append(CHARACTER_SETS[char][0])
        else:
            output.append(char)
    return ''.join(output)


# ---------- 密码学函数 ----------
def derive_pbkdf2_key(password, salt, key_length, iterations=PBKDF2_ITERATIONS, hash_algorithm='sha256'):
    """使用PBKDF2-HMAC算法派生密钥"""
    return hashlib.pbkdf2_hmac(hash_algorithm, convert_to_bytes(password), salt, iterations, key_length)


def hkdf_extract(salt, input_keying_material, hash_function=HKDF_HASH_FUNCTION):
    """HKDF提取步骤"""
    return hmac.new(salt or b'', input_keying_material, hash_function).digest()


def hkdf_expand(pseudo_random_key, info, length, hash_function=HKDF_HASH_FUNCTION):
    """HKDF扩展步骤"""
    output_keying_material = b''
    current_block = b''
    block_index = 1

    while len(output_keying_material) < length:
        current_block = hmac.new(pseudo_random_key, current_block + convert_to_bytes(info) + bytes([block_index]),
            hash_function).digest()
        output_keying_material += current_block
        block_index += 1

    return output_keying_material[:length]


def derive_encryption_keys(password, salt):
    """派生AES和ChaCha20加密所需的密钥"""
    # 使用PBKDF2生成主密钥
    pbkdf2_key = derive_pbkdf2_key(password, salt, 64)  # 512 bits

    # HKDF提取步骤
    hkdf_pseudo_random_key = hkdf_extract(b'', pbkdf2_key)

    # HKDF扩展步骤生成AES-CTR密钥 (256 bits = 32 bytes)
    aes_key = hkdf_expand(hkdf_pseudo_random_key, 'AES-CTR', 32)

    # HKDF扩展步骤生成ChaCha20密钥 (256 bits = 32 bytes)
    chacha_key = hkdf_expand(hkdf_pseudo_random_key, 'ChaCha20', 32)

    return aes_key, chacha_key


# ---------- 加密函数 ----------
def encrypt(plaintext, password=DEFAULT_PASSWORD, is_base64_enabled=False):
    """加密函数，支持标准Base64和中文Base64编码的输出"""
    # 生成盐值
    salt = os.urandom(16)

    # 派生加密密钥
    aes_key, chacha_key = derive_encryption_keys(password, salt)

    # 压缩明文
    compressed = zlib.compress(convert_to_bytes(plaintext))

    # AES-CTR加密 - 使用正确的计数器设置
    nonce = os.urandom(AES_BLOCK_SIZE - AES_COUNTER_LENGTH)  # 剩余字节作为随机数
    aes_cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    aes_ctr_encrypted = aes_cipher.encrypt(compressed)
    aes_ctr_encrypted_with_nonce = nonce + aes_ctr_encrypted

    # ChaCha20-Poly1305加密
    nonce = os.urandom(12)
    chacha_cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=nonce)
    chacha_encrypted, tag = chacha_cipher.encrypt_and_digest(aes_ctr_encrypted_with_nonce)
    chacha_encrypted_with_nonce = nonce + chacha_encrypted + tag

    # 合并盐值和加密数据
    combined = salt + chacha_encrypted_with_nonce

    # 编码为Base64
    result = base64.b64encode(combined).decode('utf-8')

    if not is_base64_enabled:
        result = base64_to_chinese(result)

    return result


# ---------- 解密函数 ----------
def decrypt(ciphertext, password=DEFAULT_PASSWORD):
    """解密函数，支持标准Base64和中文Base64编码的密文"""
    # 如果密码为空，使用默认密码
    if password == "":
        password = DEFAULT_PASSWORD

    try:
        # 检查是否为标准Base64编码
        base64.b64decode(convert_to_bytes(ciphertext), validate=True)
        processed_ciphertext = ciphertext
    except Exception:
        # 转换中文Base64为标准Base64
        processed_ciphertext = chinese_to_base64(ciphertext)

    # 解码Base64数据
    raw_data = base64.b64decode(processed_ciphertext)

    # 提取盐值和加密数据
    salt = raw_data[:16]
    encrypted_data = raw_data[16:]

    # 派生加密密钥
    aes_key, chacha_key = derive_encryption_keys(password, salt)

    # ChaCha20-Poly1305解密
    nonce = encrypted_data[:12]
    encrypted_body = encrypted_data[12:]
    ciphertext_part = encrypted_body[:-16]
    authentication_tag = encrypted_body[-16:]

    chacha_cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=nonce)
    aes_ctr_encrypted_data = chacha_cipher.decrypt_and_verify(ciphertext_part, authentication_tag)

    # AES-CTR解密 - 使用正确的计数器设置
    nonce = aes_ctr_encrypted_data[:AES_BLOCK_SIZE - AES_COUNTER_LENGTH]
    aes_encrypted_data = aes_ctr_encrypted_data[AES_BLOCK_SIZE - AES_COUNTER_LENGTH:]

    aes_cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    compressed_data = aes_cipher.decrypt(aes_encrypted_data)

    # 解压缩数据
    plaintext = zlib.decompress(compressed_data)
    return bytearray_to_string(plaintext)


def suiyue_decode(ciphertext, password=''):
    """随曰解密接口函数，支持错误处理"""
    if password == "":
        try:
            return decrypt(ciphertext)
        except Exception as e:
            return "Error:{}".format(str(e))
    else:
        try:
            return decrypt(ciphertext, password)
        except Exception as e:
            return "Error:{}".format(str(e))


def suiyue_encode(plaintext, password=DEFAULT_PASSWORD, is_base64_enabled= False):
    """随曰加密接口函数，支持错误处理"""
    if password == "":
        try:
            return encrypt(plaintext)
        except Exception as e:
            return "Error:{}".format(str(e))
    else:
        try:
            return encrypt(plaintext, password, is_base64_enabled)
        except Exception as e:
            return "Error:{}".format(str(e))

if __name__ == '__main__':
    # 测试用例
    plaintext = "心随性起、意随情生、时随运转、地随缘现、言随风散。"
    password = "随曰"

    ciphertext = suiyue_encode(plaintext, password)
    print("加密结果:", ciphertext)

    decrypted_text = suiyue_decode(ciphertext, password)
    print("解密结果:", decrypted_text)