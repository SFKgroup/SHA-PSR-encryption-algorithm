import os
import json
# --config--

# --常量--
# 常量存储目录
const_dir = './__const__'
if not os.path.isdir(const_dir):os.mkdir(const_dir)
# 设置文件名
local_setting = os.path.join(const_dir,'setting.json')
# 质数文件名
prime_filepath = os.path.join(const_dir,'prime.json')
# 存储质数表的变量
prime_list = []

# --默认设置--
# 密码暂存目录
key_dir = './__key__'
# 是否暂存密码
is_write_key = True
# 最大密码运算位数(128的n倍)
key_n = 1000
# 日志文件的位置
log_path = './log.txt'
# 是否控制台输出
console = True

# 读取本地设置
if os.path.isfile(local_setting):
    with open(local_setting,'r',encoding='utf-8') as g:local = json.loads(g.read())

    key_dir =      local['key_dir']
    is_write_key = local['is_write_key']
    key_n =        local['key_n']
    log_path =     local['log_path']
    console =      local['console']
else:
    local = {}
    local['key_dir'] = key_dir
    local['is_write_key'] = is_write_key
    local['key_n'] = key_n 
    local['log_path'] = log_path  
    local['console'] = console

    with open(local_setting,'w',encoding='utf-8') as g:g.write(json.dumps(local))

# 初始化
if not os.path.isdir(key_dir):os.mkdir(key_dir)
if log_path:logger = open(log_path,'w').close()
keylen = key_n*128+2
prime_filepath = os.path.join(const_dir,'prime.json')