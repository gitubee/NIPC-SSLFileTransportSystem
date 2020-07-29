import socket
import re
import ssl,time,os,struct,tkinter

class client_ssl:
    def __init__(self,addr='127.0.0.1',port=9999):
        # 生成SSL上下文
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # 加载信任根证书
        context.load_verify_locations('./cer/CA/ca.crt')
        # 加载客户端所用证书和私钥
        context.load_cert_chain('./cer/client/client.crt', './cer/client/client_rsa_private.pem')
        # 双向校验模式
        context.verify_mode = ssl.CERT_REQUIRED

        # 与服务端建立socket连接
        self.sock = socket.create_connection((addr, port))

        # 将socket打包成SSL socket
        # 一定要注意的是这里的server_hostname是指服务端证书中设置的CN
        self.ssock = context.wrap_socket(self.sock, server_hostname='SERVER', server_side=False)
        #包含当前云端的所有文件，subfiles为子文件夹，files为文件
        self.now_files=[]
        self.now_subfiles=[]
        #记录当前操作的云端文件路径
        self.server_path='./'
        self.client_path='./ClientCache/'

    def login(self,username,password):
        # 打包文件头信息，并打包用户信息，用于注册
        data_pack=user_name+';'+password
        data_pack=data_pack.encode('utf-8')
        head_info=struct.pack('I',5,len(data_pack))
        self.ssock.send(head_info)
        self.ssock.send(data_pack)
        print('Under registration...')
        buf = self.ssock.recv(8)
        
        if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            ret_type=struct.unpack('I',buf[0:4])
            data_size=struct.unpack('I',buf[4:8])
            if ret_type is 0:
                return False
            ret_data=self.ssock.recv(data_size).decode('utf-8')
            all_subfiles,all_files=re.split(';',ret_data)
            self.all_subfiles=re.split(':',all_subfiles)
            self.all_files=re.split(':',all_files)
            return True
        else:
            return False

    def upload(self,file_path):
        if os.path.isfile(file_path):
            
            #首先发送上传请求包，请求上传
            file_name=os.path.basename(file_path).encode('utf-8')
            req_head=struct.pack('I',12,len(filen_ame))
            self.ssock.send(req_head)
            self.ssock.send(file_name)

            buf=self.ssock.recv(8)
            if not buf:
                print('no return from server!')
                return False
            ret_type=struct.unpack(buf[0:4])
            if ret_type is not 1:
                print('server deny request!')
                return False
            #获得了服务器的许可，开始传输文件
            file_size=os.stat(file_path).st_size
            send_head=struct.pack('I',16,file_size)
            self.ssock.send(send_head)
            #将文件数据分批传送
            fo = open(file_path, 'rb')
            while True:
                file_data = fo.read(1024)
                if not file_data:
                    break
                self.ssock.send(file_data)
            fo.close()
            print('send over...')
            tkinter.messagebox.showinfo('提示！', message='上传成功')
            #self.ssock.close()
        else:
            print('ERROR FILE')
            
    def update(self):
        #更新当前云端的文件夹内容到本地
        req_head=struct.pack('I',13,0)
        self.ssock.send(req_head)

        buf=self.ssock.recv(8)
        if buf:
            #读取服务器数据
            ret_type=struct.unpack('I',buf[0:4])
            data_size=struct.unpack('I',buf[4:8])
            if ret_type is 0:
                return False
            #拆解子文件名，子目录名并分别存储
            file_data=self.ssock.recv(data_size)
            file_str=file_data.decode('utf-8')
            subfiles,files=re.split(';',file_str)
            self.now_subfiles=re.split(':',subfiles)
            self.now_files=re.split(':',files)
            print('Success read subdir：'+subfile_name)
        else:
            return False
        
    def newsubfile(self,subfile_name):
        readsubfile(self,subfile_name,13)
        return
    def readsubfile(self,subfile_name,pack_type=12):
        #进入云端当前文件下子目录
        subfile_name_data=subfile_name.encode('utf-8')
        
        req_head=struct.pack('I',pack_type,len(subfile_name_data))
        self.ssock.send(req_head)
        self.ssock.send(subfile_name_data)

        buf=self.ssock.recv(8)
        if buf:
            #读取服务器数据
            ret_type=struct.unpack('I',buf[0:4])
            data_size=struct.unpack('I',buf[4:8])
            if ret_type is 0:
                return False
            #拆解子文件名，子目录名并分别存储
            file_data=self.ssock.recv(data_size)
            file_str=file_data.decode('utf-8')
            subfiles,files=re.split(';',file_str)
            self.now_subfiles=re.split(':',subfiles)
            self.now_files=re.split(':',files)
            print('Success read subdir：'+subfile_name)
        else:
            return False

        
    def download(self, file_name):
        # 定义文件头信息，包含文件名和文件大小
        #首先发送下载请求包，请求下载

        file_name_data=file_name.encode('utf-8')
        req_head=struct.pack('I',13,len(file_name_data))
        self.ssock.send(req_head)
        self.ssock.send(file_name_data)

        buf1=self.ssock.recv(8)
        if not buf:
            print('no return from server!')
            return False
        ret_type=struct.unpack(buf1[0:4])
        if ret_type is not 1:
            print('server deny request!')
            return False
        buf2=self.ssock.recv(8)
        
        if buf2:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            ret_type=struct.unpack('I',buf2[0:4])
            file_size=struct.unpack('I',buf2[4:8])
            if ret_type is 16:
                
                file_path = os.path.join('./ClientDownload/', file_name)
                print('file new name is %s, filesize is %s' % (file_path, file_size))
                recvd_size = 0  # 定义接收了的文件大小
                file = open(file_path, 'wb')
                print('start receiving...')
                while not recvd_size == file_size:
                    if fileSize - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize - recvd_size)
                        recvd_size += len(rdata)
                    file.write(rdata)
                file.close()
                print('receive done')
                
                tkinter.messagebox.showinfo('提示！',message='下载成功：' + file_name)
                return True

            else:
                return False


    def register(self,user_name,password):
        # 打包文件头信息，并打包用户信息，用于注册
        data_pack=user_name+';'+password
        data_pack=data_pack.encode('utf-8')
        head_info=struct.pack('I',4,len(data_pack))
        self.ssock.send(head_info)
        self.ssock.send(data_pack)
        print('Under registration...')
        buf = self.ssock.recv(8)
        
        if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            ret_type=struct.unpack('I',buf[0:4])
            data_size=struct.unpack('I',buf[4:8])
            if ret_type is 0:
                return False
            ret_data=self.ssock.recv(data_size).decode('utf-8')
            all_subfiles,all_files=re.split(';',ret_data)
            self.all_subfiles=re.split(':',all_subfiles)
            self.all_files=re.split(':',all_files)
            return True
        else:
            return False
            
            


if __name__ == "__main__":
    client = client_ssl()
    filepath = 'SecureTransfer-master/Project/cer/server/server.crt'
    client.login('lindada','lindada')
    client.upload(filepath)
