import socket
import re
import ssl, threading, struct,os
import time

'''
应用层协议
    结构：8字节 4字节标记符，四字节指示文件长度，剩余为数据
    
    
    
主要功能：
    0     错误返回  S
    1     正确返回  S
    2
    3
    4     注册与确认      C
    5     登录与确认      C
    6     注销/强制下线      C/S
    7
    8     新建子目录/返回目录    C/S
    9     更新访问目录    C
    10
    11
    12     上传文件请求  C 
    13     下载文件请求  C 
    14     删除文件请求  C
    15
    16     文件流传输  C/S
    
    
    
'''



class server_ssl:
    def __init__(self,ip_address='127.0.0.1',port=9999):
        self.all_user_password={}
        self.ip=ip_address
        self.listen_port=port
        if not os.path.exists('./ServerRec/'):
            os.mkdir('./ServerRec/')
        return
    def server_listen(self):
        # 生成SSL上下文
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # 加载信任根证书
        context.load_verify_locations('./cer/CA/ca.crt')
        # 加载服务器所用证书和私钥
        context.load_cert_chain('./cer/server/server.crt', './cer/server/server_rsa_private.pem')
        # 双向校验模式
        context.verify_mode = ssl.CERT_REQUIRED

        # 监听端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', 9999))
            sock.listen(5)
            # 将socket打包成SSL socket
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    # 接收客户端连接
                    print('start server.....')
                    connection, addr = ssock.accept()
                    print('Connected by ', addr)
                    #开启多线程,这里arg后面一定要跟逗号，否则报错
                    thread = threading.Thread(target=self.conn_thread, args=(connection,addr,))
                    thread.start()

    def conn_thread(self,connection,addr):
        #包含是否有用户，当前用户，当前文件目录，当前操作文件，当前目录层次，上一个包类型
        have_user=False
        user_name=''
        now_dir='./ServerRec/'
        now_subfiles=[]
        now_files=[]
        op_file=''
        now_level=0
        pre_command=1
        while True:
            try:
                connection.settimeout(5)
                fileinfo_size = 8
                buf = connection.recv(fileinfo_size)
                if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
                    command=struct.unpack('I',buf[0:4])
                    data_size=struct.unpack('I',buf[4:8])
                    
                    #如果用户没有登录，则驳回一切非登录注册包
                    if not have_user and (command is not 5 and command is not 4):
                        error_ret=struct.pack('I',0,0)
                        connection.send(error_ret)
                        continue
                    pre_command=command
                    
                    #当有用户注册请求包
                    if command == 4:
                        # 获取用户想要注册的用户名，以及注册密码
                        user_data=connection.recv(data_size)
                        user_data=struct.unpack('s',user_data)
                        user_data=re.split(';',user_data)
                        new_user_name=user_data[0]
                        new_user_password=user_data[1]
                        #当用户名已存在时，驳回注册请求
                        if new_user_name in self.all_user_password:
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        #否则，给该用户注册,并自动登录该用户
                        self.all_user_password[new_user_name]=new_user_password
                        have_user=True
                        user_name=new_user_name

                        #记录注册记录
                        now_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        logdata='time:%s  addr:%s  username:%s  opetion:Register\n'%(now_time,str(addr),user_name)
                        with open('./logfile.txt','a+',encoding='utf-8') as fp:
                            fp.write(logdata)
                        fp.close()
                        
                        #给该用户发送成功注册提示，并发送文件目录，用于后续操作
                        gen_file=os.walk(now_dir)
                        now_root,now_subfiles,now_files=next(gen_file)
                        if now_level is not 0:
                            now_subfiles.append('.')
                            now_subfiles.append('..')
                        send_pack=':'.join(now_subfiles)+';'+':'.join(now_files)
                        send_pack=send_pack.encode('utf-8')
                        ok_ret=struct.pack('I',8,len(send_pack))
                        connection.send(ok_ret)
                        connection.send(send_pack)
                        
                        #当前收到的为用户登录请求包时
                    elif command == 5:
                        # 获取用户想要注册的用户名，以及注册密码
                        user_data=connection.recv(data_size)
                        user_data=struct.unpack('s',user_data)
                        user_data=re.split(';',user_data)
                        user_name=user_data[0]
                        user_password=user_data[1]
                        #当用户名不存在时，驳回注册请求
                        if user_name not in self.all_user_password:
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                            #用户密码有误时，驳回该请求
                        elif self.all_user_password[user_name] is not user_password:
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        #否则，给该用户登录
                        have_user=True

                        #记录登录记录
                        now_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        logdata='time:%s  addr:%s  username:%s  opetion:Login\n'%(now_time,str(addr),user_name)
                        with open('./logfile.txt','a+',encoding='utf-8') as fp:
                            fp.write(logdata)
                        fp.close()
                        
                        #给该用户发送成功登录提示，并发送文件目录，用于后续操作
                        gen_file=os.walk(now_dir)
                        now_root,now_subfiles,now_files=next(gen_file)
                        #
                        if now_level is not 0:
                            now_subfiles.append('.')
                            now_subfiles.append('..')
                        send_pack=':'.join(now_subfiles)+';'+':'.join(now_files)
                        send_pack=send_pack.encode('utf-8')
                        ok_ret=struct.pack('I',8,len(send_pack))
                        connection.send(ok_ret)
                        connection.send(send_pack)

                        
                    elif command is 6:
                        #如果决定注销
                        connection.close()
                        break
                        
                    elif command is 8:
                        #如果当前客户端请求新建目录
                        
                        path_data=connection.recv(data_size)
                        path_name=path_data.decode('utf-8')
                        #如果请求建立非法目录
                        if '/' in file_name or '\\' in file_name or '.' in file_name or file_name is '':
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        else:
                            #如果建立合法目录或者已存在目录
                            sub_dir=os.path.join(now_dir,file_name)
                            if not os.path.exists(sub_dir):
                                os.mkdir(sub_dir)
                                now_subfiles.append(file_name)
                            #发送更新后的数据包
                            send_pack=':'.join(now_subfiles)+';'+':'.join(now_files)
                            send_pack=send_pack.encode('utf-8')
                            send_head=struct.pack('I',8,len(send_pack))
                            connection.send(send_head)
                            connection.send(send_pack)
                        #记录建立文件夹记录
                        now_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        logdata='time:%s  addr:%s  username:%s  opetion:new file  now path:%s  file name:%s\n'%(now_time,str(addr),user_name,now_dir,file_name)
                        with open('./logfile.txt','a+',encoding='utf-8') as fp:
                            fp.write(logdata)
                        fp.close()
                        
                    elif command is 9:
                        #如果客户端请求更新当前目录,进入子目录,返回根f目录，请求返回上层目录
                        #数据为0，说明请求获取当前子目录
                        if data_size is 0:
                            now_dir=now_dir
                        else:
                            path_data=connection.recv(data_size)
                            path_name=path_data.decode('utf-8')
                            #如果请求回到根目录
                            if path_data is '.':
                                now_level=0
                                now_dir='./ServerRec/'
                                #如果请求返回上级目录，则判断是否到达根
                            elif path_data is '..':
                                if now_level is 0:
                                    error_ret=struct.pack('I',0,0)
                                    connection.send(error_ret)
                                    continue
                                now_level=now_level-1
                                now_dir=os.path.dirname(now_dir)
                                #如果文件名非法
                            elif '/' in file_name or '\\' in file_name or '.' in file_name:
                                error_ret=struct.pack('I',0,0)
                                connection.send(error_ret)
                                continue
                            else:
                                now_dir=os.path.join(now_dir,file_name)
                                if not os.path.exists(now_dir):
                                    os.mkdir(now_dir)
                        #统一处理后，得到要操作的文件目录，获取子目录与文件  
                        gen_file=os.walk(now_dir)
                        now_root,now_subfiles,now_files=next(gen_file)
                        if now_level is not 0:
                            now_subfiles.append('.')
                            now_subfiles.append('..')
                        send_pack=':'.join(now_subfiles)+';'+':'.join(now_files)
                        send_pack=send_pack.encode('utf-8')
                        send_head=struct.pack('I',8,len(send_pack))
                        connection.send(send_head)
                        connection.send(send_pack)
                        
                        #记录读取记录
                        now_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        logdata='time:%s  addr:%s  username:%s  opetion:scan file  now path:%s\n'%(now_time,str(addr),user_name,now_dir)
                        with open('./logfile.txt','a+',encoding='utf-8') as fp:
                            fp.write(logdata)
                        fp.close()
                        
                        #当前包为上传请求包时
                    elif Command is 12:
                        file_name=connection.recv(data_size)
                        file_name=file_name.decode('utf-8')
                        #如果新的文件名中有/，可能存在安全问题，驳回上传请求
                        if '/' in file_name or '\\' in file_name:
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        
                        #得到当前操作文件名，用于后续操作,同时检查是否已有该文件，若已有则驳回
                        op_file=os.path.join(now_dir,file_name)
                        '''
                        if os.path.isfile(op_file):
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        '''
                        #记录上传记录
                        now_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        logdata='time:%s  addr:%s  username:%s  opetion:upload file  now path:%s   new file:%s\n'%(now_time,str(addr),user_name,now_dir,file_name)
                        with open('./logfile.txt','a+',encoding='utf-8') as fp:
                            fp.write(logdata)
                        fp.close()
                        #告诉客户端可以开始传输数据了
                        now_files.append(file_name)
                        ok_ret=struct.pack('I',1,0)
                        connection.send(ok_ret)
                        
                        #当前包为下载请求包时
                    elif command is 13:
                        file_name=connection.recv(data_size)
                        file_name=file_name.decode('utf-8')
                        #如果新的文件名中有/，可能存在安全问题，驳回下载请求
                        if '/' in file_name or '\\' in file_name:
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        #得到当前操作文件名，用于后续操作,同时检测当前文件名是否存在
                        op_file=os.path.join(now_dir,file_name)
                        if not os.path.isfile(op_file):
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue

                        #记录下载记录
                        now_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        logdata='time:%s  addr:%s  username:%s  opetion:download file  now path:%s   file:%s\n'%(now_time,str(addr),user_name,now_dir,file_name)
                        with open('./logfile.txt','a+',encoding='utf-8') as fp:
                            fp.write(logdata)
                        fp.close()
                        
                        #服务器开始给客户端发送文件数据流
                        file_size=os.stat(op_file).st_size
                        ok_ret=struct.pack('I',16,file_size)
                        connection.send(ok_ret)
                        #读取文件数据，并按1024为每个批次开始传输
                        fo = open(filepath, 'rb')
                        while True:
                            filedata = fo.read(1024)
                            if not filedata:
                                break
                            connection.send(filedata)
                        fo.close()
                        print('send file over...')
                        
                        #当前包为上传数据流包
                    elif command is 16:
                        #如果没有收到上传请求，则立刻驳回
                        if pre_command is not 12:
                            error_ret=struct.pack('I',0,0)
                            connection.send(error_ret)
                            continue
                        
                        recvd_size = 0  # 定义接收了的文件大小
                        file = open(op_file, 'wb')
                        print('start receiving...')
                        #按每个批次1024字节接收数据
                        while not recvd_size == data_size:
                            if data_size - recvd_size > 1024:
                                rdata = connection.recv(1024)
                                recvd_size += len(rdata)
                            else:
                                rdata = connection.recv(fileSize - recvd_size)
                                recvd_size += len(rdata)
                            file.write(rdata)
                        file.close()
                        print('receive done')
                        
                    else:
                        connection.close()

            except socket.timeout:
                connection.close()
                break
            except ConnectionResetError:
                connection.close()
                break

if __name__ == "__main__":
    server = server_ssl()
    server.server_listen()
