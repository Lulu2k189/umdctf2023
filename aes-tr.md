# Đề bài
```
import socket
import random
import threading
from _thread import *
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from Crypto.Util.strxor import strxor
from binascii import hexlify, unhexlify

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 60000        # Port to listen on (non-privileged ports are > 1023)
FLAG = open('flag.txt', 'r').read().strip()
MENU = "\nWhat would you like to do?\n\t(1) Encryption Query\n\t(2) Check Bit\n\t(3) Exit\n\nChoice: "
INITIAL = "Welcome to the best symmetric encryption scheme ever. I'll give you a flag if you can prove this scheme insecure under IND-CPA, but I know it's impossible!! >:)\n"

BS = 16 # Block Size
MS = 30 # Maximum blocks per query
MAX_QUERIES = 10
NUM_BITS = 128

def encrypt(m):
    m = unhexlify(m)
    iv = Random.get_random_bytes(16)
    key = Random.get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    blocks = [m[i:i+BS] for i in range(0, len(m), BS)]
    ct = iv
    for i in range(len(blocks)):
        ctr = l2b((b2l(iv)+i+1) % pow(2,BS*8))
        ctr = b'\x00'*(BS - len(ctr)) + ctr # byte padding if ctr < pow(2,BS*8 - 1)
        ct += cipher.encrypt(strxor(ctr, blocks[i]))

    assert len(ct) - len(m) == BS
    return hexlify(ct)
    

def threading(conn):
    conn.sendall(INITIAL.encode())

    for bit in range(NUM_BITS):
        queries = 0
        b = random.randint(0,1)
        while queries < MAX_QUERIES:
            conn.sendall(MENU.encode())
            try:
                choice = conn.recv(1024).decode().strip()
            except ConnectionResetError as cre:
                return

            # ENCRYPTION QUERY
            if choice == '1':
                queries += 1
                conn.sendall(b'm0 (hex): ')
                m0 = conn.recv(1024).strip()
                conn.sendall(b'm1 (hex): ')
                m1 = conn.recv(1024).strip()

                if (len(m0) % 2 != 0) or ((len(m0) // 2) % BS != 0) or ((len(m0) // (2*BS)) > MS):
                    conn.sendall(b'invalid m0\n')
                elif (len(m1) % 2 != 0) or ((len(m1) // 2) % BS != 0) or ((len(m1) // (2*BS)) > MS):
                    conn.sendall(b'invalid m1\n')
                elif len(m0) != len(m1):
                    conn.sendall(b'messages must be same length\n')
                else:
                    if b == 0:
                        ct = encrypt(m0)
                    else:
                        ct = encrypt(m1)
                    conn.sendall(b'ct: ' + ct + b'\n')
                    continue

            # CHECK BIT
            elif choice == '2':
                conn.sendall(b'Bit (b) guess: ')
                b_guess = conn.recv(1024).strip().decode()
                if b_guess == str(b):
                    conn.sendall(b'correct!\n')
                    break
                else:
                    conn.sendall(b'wrong\n')
            
            # EXIT
            elif choice == '3':
                conn.sendall(b'bye homie\n')
            
            # INVALID
            else:
                conn.sendall(b'invalid menu choice\n')

            # close connection on exit, invalid choice, wrong bit guess, invalid encryption query
            conn.close()
            return

        if queries > MAX_QUERIES:
            conn.sendall(f'too many queries: {queries}\n'.encode())
            conn.close()
            return
            
    # Bits guessed correctly
    conn.sendall(f'okay, okay, here is your flag: {FLAG}\n'.encode())
    conn.close()


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            print(f'new connection: {addr}')
            start_new_thread(threading, (conn, ))
        s.close()


```
# Cách giải
## Phân tích đề bài
Ở đây chúng ta có 1 vòng for lặp trong 128 lần, và biến b có giá trị là 0 hoặc 1 trong mỗi lần lặp

![image](https://user-images.githubusercontent.com/122846300/235393610-2291118e-58a6-44d1-8254-43fe6328ec5f.png)

Có 3 Option mà ta có thể dùng:
  - Option 1: cho phép nhập đầu vào `m0` và `m1`. Len của cả 2 phải bằng nhau, bằng bội số của block size (16) (VD 32,48...) và không vượt quá 30 block. Nếu nhập đúng hết thì tùy thuộc vào bit b ở trên mà cho `m0` hay `m1` vào function encrypt

  ![image](https://user-images.githubusercontent.com/122846300/235393996-ac7c7931-d72f-4683-9af0-e066419d1729.png)

  - Option 2: Đoán bit trong vòng lặp này, nếu đoán trúng thì lặp tiếp, không thì shutdown

  ![image](https://user-images.githubusercontent.com/122846300/235394073-1c3f0960-b1a5-46b6-8800-6b877b998585.png)

  - Option 3: Exit (cái này kệ nó đi, chả quan tâm đâu)

Như vậy, có thể thấy ý tưởng là tìm được bit b tại Option 1, sau đó ném vào Option 2. Lặp lại liên tục như vậy 128 vòng sẽ có flag

![image](https://user-images.githubusercontent.com/122846300/235394389-fbddd067-2096-4ea7-93ed-bee14a96f590.png)

Tiếp theo, ta xem hàm Encrypt

![image](https://user-images.githubusercontent.com/122846300/235394457-e727431c-36e9-40b1-b100-4c280eb63f86.png)

Hàm này sử dụng AES-ECB, có key và iv là 16 bytes random (wtf, sao lại có iv ở ECB)

Tiếp đó, đầu vào `m` được chia thành các khối len 16 bytes, trở thành phần tử của list `blocks`

Tại line 29, gán ct=iv, mục đích là để phần output có chứa iv

Tại line 31, đổi iv từ bytes sang int, mỗi khối + i+1, sau đó lại chuyển sang bytes (phần % pow kệ nó đi, số thì bé mod vẫn thế thôi, không thay đổi gì cả)

![image](https://user-images.githubusercontent.com/122846300/235395593-42f230d0-34c9-4740-b4b0-dcaa7dd12b64.png)

Tại line 32, padding byte `\x00` vào phía bên trái sao cho len của `ctr` bằng bội số của block size (bước này không ảnh hưởng gì cả, như ở line 31 thì nó vẫn là 16 bytes thôi, không padding thêm)

Tại line 33, encrypt AES.MODE_ECB với input là xor(ctr, blocks[i]) 

Để ý dòng 35, output của ta sẽ gồm iv+encrypt(block1)+encrypt(block2).... 

## Giải đề 
Điểm đáng nhớ nhất của mode ECB là 2 ciphertext giống hệt nhau sẽ cho ra 2 plaintext giống nhau. Tức là ta phải làm cái gì đó để output có 2 khối giống nhau.

Ý tưởng là nhập `m0` là một chuối, sao cho khi qua hàm Encrypt xử lý ta có được 2 khối giống nhau. Và `m1` sẽ là 1 chuỗi bất kỳ. Như vậy, bằng việc tìm xem output có 2 khối giống nhau hay không, ta có thể đoán được biến b là 0 hay 1

Như với mỗi bài ECB, điều đầu tiên nhảy ra trong đầu mình là 16 bytes `\x00`.

Nhưng mà nó có quả xor(ctr, blocks[i]) :).. cay thế nhể :)

Phép xor cũng có cái hay của nó. `ctr` chính là int(iv) + 1... Điều này dẫn đến ý tưởng sử dụng các block bytes `\x00`, trong đó có 1 block duy nhất kết thúc bằng `\x01`

Như thế sẽ có 2 trường hợp trả về 2 block giống nhau:

![image](https://user-images.githubusercontent.com/122846300/235401974-a666122b-b437-4ede-a9a3-a66234ad1969.png)

Giả sử ta cho Block2 là `\x00` *15 + `\x01`, 

TH1: bin của ctr tại block 1 kết thúc bằng `1`

![image](https://user-images.githubusercontent.com/122846300/235404999-702a4db3-dfd8-440b-9e37-4f3a5d7421ae.png)


TH2: bin của ctr tại block 1 kết thúc bằng `0`

![image](https://user-images.githubusercontent.com/122846300/235405091-59db449b-6aac-458d-b99b-7b553d871b7c.png)

Chính vì có 2 trường hợp như này mà khi nhập input < 3 block(48 bytes), hay đặt block kết thúc `\x01` ở các vị trí block đầu hay cuối của input trong khi chạy sẽ có thể không xuất hiện 2 block giống nhau mặc dù biến b=0

Đến đây là ra rồi đấy :)

solved.py
```
from pwn import *

context.log_level='debug'

host = "0.cloud.chals.io"
port = 24524
r = remote(host,port)
m0 = '00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000'
m1 = '11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222'

for i in range(128):
    r.recvuntil(b"Choice:")
    r.sendline(b"1")
    r.recvuntil(b"m0 (hex): ")
    r.sendline(m0.encode())
    r.recvuntil(b"m1 (hex): ")
    r.sendline(m1.encode())
    r.recvuntil(b"ct: ")
    ct = r.recvline().strip().decode()
    print(r.recvline())
    l = ['0']*5
    for j in range(5):
        l[j]=ct[32*j:32*(j+1)]
    r.recvuntil(b"Choice: ")
    r.sendline(b"2")
    r.recvuntil(b"Bit (b) guess: ")
    if l[1]==l[2] or l[2]==l[3]:
        r.sendline(b"0")
    else: 
        r.sendline(b"1")
    print(r.recvline())

    
print(r.recvline())
print(r.recvline())
```


