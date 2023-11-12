# 基于SHA与素数平方根的快速加密算法 (FisherCodev3)

### 一、使用

通过传参的方式调用`key_operate.py`进行加密与解码。

```bash
optional arguments:
  -h, --help       show this help message and exit
  --input INPUT    File or dir which needs to be encoded
  --output OUTPUT  Path(Dir) which put the results
  --key KEY        Key you set
  --echo           Print the output
  --encode         Use encode
  --decode         Use decode
```

```bash
python key_operate.py --encode --input xxx.xx --output ./out --key 123456
```

```bash
python key_operate.py --decode --input xxx.fc --output ./out --key 123456
```

加密时支持传入目录，将加密目录下所有文件为一个文件(先压缩，再对压缩包加密)

### 二、选项

在`./__const__/setting.json`内存有一些可变的设定。

```json
{
	"key_dir": "./__key__", // 存放密码的目录(存储密码会降低安全性，但可以节省出计算密码数据的时间)
	"is_write_key": true,   // 是否存储密码(存储密码会降低安全性，但可以节省出计算密码数据的时间)
	"key_n": 1000,          // 密码数据单元长度(越大越安全，但会增加计算密码数据的时间，500约为19s，1000约为45s)
	"log_path": "./log.txt",// 日志文件路径
	"console": true         // 是否控制台输出(直接传参时无效)
}
```

### 三、原理

1. 计算得到*65536*以内所有的质数，并顺序存储 (作为常量，换取运算速率)

2. 获取混淆扩增的密钥组

   $$
   (1) 将密钥字符串编码为UTF-8后求取其SHA3-512值 \\
   (2) 将128bit的SHA-512以每4bit一份的长度分成32份 \\
   (3) 将每一份转换为10进制数，记作 a_n (n \in N^*,n\le 32) \\
   (4) 若 a_n \bmod 2 = 0 则根据哥德巴赫猜想可以被分解为两个质数和。 \\
   (5) 记所有拆分中，差值最小的质数组合为 b_n,c_n \\
   (6) 若 a_n \bmod 2 = 1 则 b_n = P_{a_n \bmod 1000} , c_n = a_n\\
   (7) d_n = \lvert \sqrt {c_n} - \sqrt{b_n} \rvert (一般情况下c_n > b_n) \\
   (8) 取d_n 的小数点后前 128*key\_n 位作为一个密码块 ，建议key\_n = 1000 \\
   (9) 以128位为一组，计算其SHA-512结果(长度也为128位)并替换 \\
   (10)将相邻的每两个密码块顺次连接，得到16个密码块为一个list即为密钥组
   $$

3. 将密钥字符串编码为UTF-8后求取其SHA256和SHA3-256值作为密钥索引

4. 读取文件长度，计算文件长度 与 密钥组长度和密钥索引长度之积 之商，向上取整。

5. 将密钥索引重复刚刚的计算结果次

6. 遍历密钥索引，以密钥组内密钥长度为单位读入数据，取以当前密钥索引值对应的密钥组与读入数据异或(两个索引异或两次)

7. 得到全部的加密数据

### 四、测试与评价

​	该方法在key_n=1000时，可以保证文件大小小于256Mb的文件很大程度的安全(此时密钥索引还未进入循环)

​	增加安全性的方法主要有提升key_n以及不在本地保存密钥组(相应地，都会损失时间)

​	算法的特点主要在于素数的平方根是无理数，不同素数的平方根之差也是无理数，利用平方根难以逆运算以及哈希难以逆运算的特点，达到了对不定长度的密码字符串进行定长度的混淆扩增。虽然加密手段选择了异或，但异或使用的密钥长度达到了key_n*256kb的大小，以及足以模糊其密钥特征，可以保证安全性。同时运算速度较快，可以快速完成大文件的加密解密。

### 五、ToDo List

​    使用快速平方根倒数方法或许可以比`math.sqrt()`快，但暂没有尝试。

|    SFKgoup |
| ---------: |
| 2023.11.01 |

