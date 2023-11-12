import decimal
import os
import config
import hashlib
import json
import math
import binascii
import py7zr
import random
import argparse
import sys

decimal.getcontext().prec = config.keylen

# 日志记录函数
def log(msg,*args,types = 'log'):
    if types == 'err':colour = 31
    elif types == 'acc':colour = 32
    else:colour = 33
    args = list(map(str,args))
    if config.console:print(f'\033[1;{colour}m{msg}\033[0m  {" ".join(args)}')
    if config.log_path:
        with open(config.log_path,'a') as logger:logger.write(f'{msg}  {" ".join(args)}\n')

# 保存密码数据
def write_kdata(hash,data:list):
    for i,d in enumerate(data):
        with open(f'./{config.key_dir}/{hash}_{i}','wb') as g:g.write(d)

# 读已保存的密码
def read_kdata(hash) -> [bytes]:
    res = []
    for i in range(16):
        if not os.path.isfile(f'./{config.key_dir}/{hash}_{i}'):return [b'']
        with open(f'./{config.key_dir}/{hash}_{i}','rb') as g:res.append(g.read())
    return res

# 质数存储修饰器
def prime_file(func):
    def inner():
        if os.path.isfile(config.prime_filepath):
            with open(config.prime_filepath,'r',encoding='utf-8') as g:config.prime_list = json.loads(g.read())
            return config.prime_list
        else:config.prime_list = func()
    return inner

# 密码存储修饰器
def key_file(func):
    def inner(key:str):
        if config.is_write_key:
            key_sh = hashlib.sha1()
            key_sh.update(key.encode('utf-8'))

            data = read_kdata(key_sh.hexdigest())
            if len(data[0]) < config.keylen-2:
                data = func(key)
                write_kdata(key_sh.hexdigest(),data)
                log('caculated finished.',types='acc')
            else:log('read finished.',types='acc')
            
            return data
        else:return func(key)
    return inner

# 质数表计算
@prime_file
def get_prime_numbers() -> list:
    log('making prime list...')
    prime_numbers = [2,3]
    for num in range(5, 16**4+1):
        for i in range(2, round(math.sqrt(num))+2):
            if num % i == 0:break
        else: prime_numbers.append(num)
        #if num % 100000 == 0:log(len(prime_numbers))
    with open(config.prime_filepath,'w',encoding='utf-8') as g:g.write(json.dumps(prime_numbers).replace(' ',''))
    return prime_numbers

# 密码数据计算
@key_file
def get_key(key:str) -> [bytes] : 
    log('start caculate key')

    sha = hashlib.sha3_512()
    sha.update(key.encode('utf-8'))
    key_sha = str(sha.hexdigest()) # 获取密码的sha512值(128位)

    sqrt_list = []
    for i in range(0,len(key_sha),4): # 以4个为一组切分
        number = int(key_sha[i:i+4],16) # 转换为10进制数number
        if number % 2 == 1:
            sqrt_list.append([config.prime_list[number%1000],number]) # 如果是奇数，取质数表的第number%1000项和number本身
            continue
        sqrt_temp_list = []
        for i in config.prime_list: # 如果是偶数，按照哥德巴赫猜想，可以拆分为两个质数和，取所有组合中最相近的两个质数
            if i >= number//2:break
            if number - i in config.prime_list:sqrt_temp_list.append(i)
        i = max(sqrt_temp_list)
        sqrt_list.append([i,number - i])
    
    numbers = []
    for num in sqrt_list:
        number_0 = decimal.Decimal(num[0])
        number_1 = decimal.Decimal(num[1])
        numbers.append(abs(number_1.sqrt() - number_0.sqrt()))# 对数对的各项平方之后作差
        if not '.' in str(numbers[-1]):log('Error.',number_0,number_1,numbers[-1])

    ret_list = []
    for i,num in enumerate(numbers):
        str_num = str(num).split('.')[1] # 取结果的小数部分
        res = b''
        for p in range(0,len(str_num),128):
            sha = hashlib.sha3_512()
            sha.update(str_num[p:p+128].encode('utf-8')) # 每128位hash一次
            res += binascii.unhexlify(str(sha.hexdigest()))
        if i % 2 == 0:ret_list.append(res) # 由于产生了32个密码块，相邻两个密码块合并，得到16个密码块
        else:ret_list[-1] += res

    return ret_list # 返回16个密码块

# 文件编码
def encode_file(file_path,key_str:str,out_path,auto_unpack = False):
    log('start encode file...')
    sha = hashlib.sha3_256()
    sha.update(key_str.encode('utf-8'))
    key_sha3 = str(sha.hexdigest())*math.ceil(os.path.getsize(file_path) / (128*config.key_n*64))
    sha = hashlib.sha256()
    sha.update(key_str.encode('utf-8'))
    key_sha = str(sha.hexdigest())*math.ceil(os.path.getsize(file_path) / (128*config.key_n*64))
    file = open(file_path,'rb')
    out = open(out_path,'wb')
    key = get_key(key_str)

    out.write(f'{os.path.split(file_path)[-1]}\n'.encode('utf-8'))
    out.write(config.key_n.to_bytes(2,'little'))
    if auto_unpack:out.write((random.randint(0,127)*2).to_bytes(1,'little'))
    else:out.write((random.randint(0,127)*2+1).to_bytes(1,'little'))
    
    for k,s in zip(key_sha,key_sha3):
        data = file.read(128*config.key_n)
        if not data:break
        out.write((int.from_bytes(data, byteorder='big')^int.from_bytes(key[int(s,16)][:len(data)], byteorder='big')^int.from_bytes(key[int(k,16)][:len(data)], byteorder='big')).to_bytes(len(data),'big'))

    file.close()
    out.close()

    return 0

# 文件解码 (0:正常解码,1:格式错误,2:密码错误)
def decode_file(file_path,key_str:str,out_dir):
    if not os.path.exists(out_dir):os.mkdir(out_dir)
    log('start decode file...')
    file = open(file_path,'rb')
    
    try:file_name = file.readline().decode('utf-8')[:-1]
    except:return 1

    key_n = int.from_bytes(file.read(2), byteorder='little')
    auto_unpack = int.from_bytes(file.read(1), byteorder='little') % 2 == 0

    sha = hashlib.sha3_256()
    sha.update(key_str.encode('utf-8'))
    key_sha3 = str(sha.hexdigest())*math.ceil(os.path.getsize(file_path) / (128*config.key_n*64))
    sha = hashlib.sha256()
    sha.update(key_str.encode('utf-8'))
    key_sha = str(sha.hexdigest())*math.ceil(os.path.getsize(file_path) / (128*config.key_n*64))
    if auto_unpack:out = open('./__temp__.7z','wb')
    else:out = open(os.path.join(out_dir,file_name),'wb')
    key = get_key(key_str)

    for k,s in zip(key_sha,key_sha3):
        data = file.read(128*key_n)
        if not data:break
        out.write((int.from_bytes(data, byteorder='big')^int.from_bytes(key[int(s,16)][:len(data)], byteorder='big')^int.from_bytes(key[int(k,16)][:len(data)], byteorder='big')).to_bytes(len(data),'big'))

    file.close()
    out.close()

    if auto_unpack:
        try:
            archive = py7zr.SevenZipFile('./__temp__.7z', mode='r')
            archive.extractall(path=out_dir)
            archive.close()
        except:return 2
        os.remove('./__temp__.7z')

    return 0

# 目录加密
def encode_dic(file_dir,key_str:str,out_path):
    archive = py7zr.SevenZipFile('./__Temp__.7z', mode='w')
    archive.writeall(path=file_dir)
    archive.close()
    encode_file('./__Temp__.7z',key_str,out_path,auto_unpack=True)
    os.remove('./__temp__.7z')

    return 0    

# 清空缓存的密码
def clear_save():
    for file in os.listdir(f'./{config.key_dir}/'):os.remove(f'./{config.key_dir}/{file}')


# 初始化
if not config.prime_list:get_prime_numbers()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, default='listen', help='File or dir which needs to be encoded')
    parser.add_argument('--output', type=str, default='', help='Path(Dir) which put the results')
    parser.add_argument('--key', type=str, default='', help='Key you set')
    parser.add_argument('--echo', action='store_false', help='Print the output')
    parser.add_argument('--encode', action='store_true', help='Use encode')
    parser.add_argument('--decode', action='store_true', help='Use decode')

    opt = parser.parse_args()

    config.console = opt.echo

    if opt.encode:
        log('Start encoding...')
        if os.path.isfile(opt.input):encode_file(opt.input,opt.key,os.path.join(opt.output,os.path.splitext(opt.input)[0]+'.fc'))
        elif os.path.isdir(opt.input):encode_dic(opt.input,opt.key,os.path.join(opt.output,os.path.splitext(opt.input)[0]+'.fc'))
        else:log('File not found',types='err')
    elif opt.decode:
        log('Start decoding...')
        res = decode_file(opt.input,opt.key,opt.output)
        if res == 1:log('Wrong file!',types='err')
        elif res == 2:log('Wrong password!',types='err')
    else:log('Unmentioned action!',types='err')
    
    log('Task finish.',types='acc')

#encode_file('./howardzhangdqs.jpg','SB','./howardzhangdqs.fc')

#encode_dic('./test','SB','./test.fc')

#decode_file('./test.fc','SB','./out')

#clear_save()
