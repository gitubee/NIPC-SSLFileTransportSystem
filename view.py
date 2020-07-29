from tkinter import *
from tkinter.messagebox import *
from tkinter import ttk
from tkinter import filedialog
import re,threading

pattern = '{"文件名": "(.*?)", "上传者": "(.*?)", "上传时间": "(.*?)", "大小": "(.*?)"}'
patch = re.compile(pattern)

class DownloadFrame(Frame):  # 继承Frame类
    def __init__(self, master=None,client=None):
        Frame.__init__(self, master)
        self.root = master  # 定义内部变量root
        self.scrollbar = Scrollbar(self.root, )
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.client = client
        self.createPage()

    def createPage(self):
        title = ['2' ]
        self.box = ttk.Treeview(self, columns=title,
                                yscrollcommand=self.scrollbar.set,
                                show='headings', height=15)

        self.box.column('2', width=300, anchor='center')
        #self.box.column('3', width=150, anchor='center')
        #self.box.column('4', width=150, anchor='center')
        #self.box.column('5', width=100, anchor='center')

        self.box.heading('2', text='文件名')
        #self.box.heading('3', text='上传者')
        #self.box.heading('4', text='上传时间')
        #self.box.heading('5', text='大小')

        self.dealline()

        self.scrollbar.config(command=self.box.yview)
        self.box.pack()

        Label(self, text=" ", fg='red').pack()
        Button(self, text=' 下载 ',command=self.download).pack(expand=1, fill="both", side="left", anchor="w")
        Button(self, text=' 退出 ', command=self.isquit).pack(expand=1, fill="both", side="left", anchor="w")


    def readdata(self, ):
        """逐行读取文件"""

        # 读取gbk编码文件，需要加encoding='utf-8'
        #f = open('./ClientCache/result.txt', 'r', encoding='utf-8')
        #line = f.readline()
        for subfile in self.client.now_subfiles:
            yield subfile
        for each_file in self.client.now_files:
            yield each_file

        return

    def dealline(self, ):
        op = self.readdata()
        x = self.box.get_children()
        for item in x:
            self.box.delete(item)
        while 1:
            try:
                line = next(op)
            except StopIteration as e:
                break
            else:
                #result = line
                self.box.insert('', 'end', values=[line])

    def isquit(self):
        is_quit = askyesno('警告', '你是否确定退出，这将会关闭窗口')
        if is_quit:
            self.quit()

    def download(self):
        curItem = self.box.focus()
        print(self.box.item(curItem))
        filename = self.box.item(curItem)['values'][0]

        showinfo('提示！', message='点击确认文件将开始后台下载')
        thread = threading.Thread(target=self.client.download, args=(filename,))
        thread.start()




class UploadFrame(Frame):  # 继承Frame类
    def __init__(self, master=None,client=None):
        Frame.__init__(self, master)
        self.root = master  # 定义内部变量root
        self.filePath = StringVar()
        self.client = client
        self.createPage()

    def createPage(self):
        Label(self).grid(row=0, stick=W, pady=10)
        Label(self, text='请选择要上传的文件: ').grid(row=1, stick=W, pady=10)
        Entry(self, textvariable=self.filePath, width=50).grid(row=1, column=1, stick=E)
        Button(self, text=' 选择文件 ', command=self.select_file).grid(row=1, column=2, stick=E, padx=10)
        Button(self, text='上传', bg='#99CCFF', command=self.upload).grid(row=2, column=1, stick=W, pady=10, ipadx=50)
        Button(self, text='重置', bg='#FF6666',command=self.reset).grid(row=2, column=1, stick=E, pady=10, ipadx=50)

    def select_file(self):
        path = filedialog.askopenfilename()  # 获得选择好的文件
        self.filePath.set(path)

    def upload(self):
        path = self.filePath.get()
        showinfo('提示！', message='点击确认文件将开始后台上传')
        # 开启线程上传
        thread = threading.Thread(target=self.client.upload, args=(path,))
        thread.start()
        self.filePath.set("")

    def reset(self):
        self.filePath.set("")


class AboutFrame(Frame):  # 继承Frame类
    def __init__(self, master=None,client=None):
        Frame.__init__(self, master)
        self.root = master  # 定义内部变量root
        self.createPage()

    def createPage(self):
        Label(self).grid(row=0, stick=W, pady=50)
        Label(self, text='Designed by justin').grid(row=1, stick=W, pady=3)
        Label(self, text='贾培养').grid(row=2, stick=W, pady=3)

# from tkinter import *
# from tkinter.messagebox import *
#
#
# class DownloadFrame(Frame):  # 继承Frame类
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.root = master  # 定义内部变量root
#         self.itemName = StringVar()
#         self.importPrice = StringVar()
#         self.sellPrice = StringVar()
#         self.deductPrice = StringVar()
#         self.createPage()
#
#     def createPage(self):
#         Label(self).grid(row=0, stick=W, pady=10)
#         Label(self, text='药品名称: ').grid(row=1, stick=W, pady=10)
#         Entry(self, textvariable=self.itemName).grid(row=1, column=1, stick=E)
#         Label(self, text='进价 /元: ').grid(row=2, stick=W, pady=10)
#         Entry(self, textvariable=self.importPrice).grid(row=2, column=1, stick=E)
#         Label(self, text='售价 /元: ').grid(row=3, stick=W, pady=10)
#         Entry(self, textvariable=self.sellPrice).grid(row=3, column=1, stick=E)
#         Label(self, text='优惠 /元: ').grid(row=4, stick=W, pady=10)
#         Entry(self, textvariable=self.deductPrice).grid(row=4, column=1, stick=E)
#         Button(self, text='录入').grid(row=6, column=1, stick=E, pady=10)
#
#
# class QueryFrame(Frame):  # 继承Frame类
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.root = master  # 定义内部变量root
#         self.itemName = StringVar()
#         self.createPage()
#
#     def createPage(self):
#         Label(self, text='查询界面').pack()
#
#
# class CountFrame(Frame):  # 继承Frame类
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.root = master  # 定义内部变量root
#         self.createPage()
#
#     def createPage(self):
#         Label(self, text='统计界面').pack()
#
#
# class AboutFrame(Frame):  # 继承Frame类
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.root = master  # 定义内部变量root
#         self.createPage()
#
#     def createPage(self):
#         Label(self, text='关于界面').pack()
