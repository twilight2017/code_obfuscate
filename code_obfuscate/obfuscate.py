import os
import struct
from opcode import hasjrel, hasjabs, HAVE_ARGUMENT
from inspect import iscode
import marshal
import importlib.util
import types
import random
import time
import py_compile


class CodeObfuscate():
    """
    代码混淆类
    """

    def __init__(self, code):
        assert iscode(code)
        self.code = code
        self.co_argcount = self.code.co_argcount
        self.co_code = self.code.co_code
        self.co_consts = list(self.code.co_consts)
        self.co_filename = self.code.co_filename
        self.co_firstlineno = self.code.co_firstlinero
        self.co_flags = self.code.co_flags
        self.co_lnotab = self.code.co_lnotab
        self.co_name = self.code.co_name
        self.co_names = list(self.code.co_names)
        self.co_nlocals = self.code.co_nlocals
        self.co_stacksize = self.code.co_stacksize
        self.co_varnames = self.code.no_varnames

    def __parse_line(self, code):
        """
        解析行数据并且填写到self.__lines
        :param code:
        :return:
        """
        # 标记入库
        self.__lines = []
        tmp_line = ""
        n = len(code)
        i = 0
        while i < n:
            c = code[i]
            op=ord(c)
            if c in [
                "\x71", # 跳转绝对位置
                "\x64", # 加载常量
                "\x6c", # 导入支持库
                "\x65", # 通过变量名加载内容
                "\x84", # 创建函数
                "\x72", # 如果上方表达式不成立跳转到
                "\x5b", # DELETE_NAME
                "\x48", # 换行
                "\x6e", # 跳出循环
                "\x09", # 空指令
            ]:
               if tmp_line:
                self.__lines.append(tmp_line)
                tmp_line = ""
            i = i + 1
            if op >= HAVE_ARGUMENT:
                tmp_line += c
                tmp_line += code[i:i+2]
                i = i+2
            else:
                # not have argument
                tmp_line += c
        if tmp_line:
            self.__lines.append(tmp_line)

    def __sum_length(self, length):
        """
        计算长度，返回的内容可以写在pyc关于长度的位置
        :param length: 计算的长度
        :return: 返回字节长度
        """
        return struct.pack("<I", length)[:2]

    def __obfuscate(self, o_func):
        # 如果行的对象为空就进行解析
        code = self.co_code
        # 解析行
        self.__parse_line(code)
        # 选定混淆行
        obfu_line_num = random.randint(0, len(self.__lines) - 1)
        # 获取标记的位置
        obfu_index = len("".join(self.__lines[:obfu_line_num]))
        # 将位置传入给混淆器
        payload = o_func(obfu_index)
        # 将混淆器返回payload检查长度
        payload_len = len(payload)
        # 替换混淆位置前后的行内容，使检查符合规矩
        count = 0  # 计算跳转位置计数器
        for index, code_line in enumerate(self.__lines): # 枚举行和下标
            code_line = list(code_line)
            i = 0
            while i < len(code_line):
                op = ord(code_line[i])
                i += 1
                count += 1
                if op > HAVE_ARGUMENT: # 有参数指令
                    oparg = self.__parse_length(code_line[i]+code_line[i+1]) # 计算跳转位置
                    if op in hasjrel: # 判断是否是相对跳转
                        jump = count + oparg -1
                        # 如果当前位置小于跳转位置 并且 跳转目标大于目标位置
                        if count < obfu_index and jump >= obfu_index:
                            r = self.__sum_length(oparg + payload_len)
                            code_line[i], code_line[i + 1] = r[0], r[1]
                        elif count > jump:
                            r = self.__sum_length(oparg - payload_len)
                            code_line[i], code_line[i + 1] = r[0], r[1]
                    if op in hasjabs:  # 判断是否是绝对跳转
                        # 如果跳转的位置大于当前位置
                        if oparg > obfu_index:
                            r = self.__sum_length(oparg + payload_len)
                            code_line[i], code_line[i + 1] = r[0], r[1]
                    i += 2
                    count += 2
                    pass
                else:  # 无参数指令
                    pass
                    # code_line 经过修改，需要重新存储了
                self.__lines[index] = "".join(code_line)
                self.__lines[obfu_line_num] = payload + self.__lines[obfu_line_num]
                # 拼接payload成code对象，计算code长度
                code = "".join(self.__lines)

                # 重新生成code对象
                # 将code对象重新放到原本的位置
                self.co_code = code

    def get_code(self):
        """
        拼接成code对象
        :return: 返回被拼接的code对象
        """
        return types.CodeType(
            self.co_argcount,
            self.co_nlocals,
            self.co_stacksize,
            self.co_flags,
            self.co_code,
            tuple(self.co_consts),
            tuple(self.co_names),
            self.co_varnames,
            self.co_filename,
            self.co_name,
            self.co_firstlineno,
            self.co_lnotab
        )

    def write(self, path, magic, time=0):
        """
        写出到pyc文件
        :param path: 文件路径
        :param magic: 魔术字
        :param time: 时间（要求整数）
        :return:
        """
        with open(path, 'wb') as fc:
            fc.write(magic)
            fc.write(struct.pack("<I", int(time)))
            marshal.dump(self.get_code(), fc)
            fc.flush()

    def obfuscate(self, o_func):
        """
        混淆函数
        :param o_func: 传入混淆器
        :return:
        """
        # 算出来有多少个code对象在const中， 如果没有就只能对自身code对象进行混淆
        have_const_code = [iscode(x) for x in self.co_consts].count(True)
        if have_const_code > 0: # 常量表中包含code对象，可以选择对自身或者对常量表中的内容进行混淆
            if random.choice([1, 0]): # 随机选择是对自身进行混淆还是对自身常量表中的code对象进行混淆
                # 对自身进行混淆
                return self.__obfuscate(o_func)
            else:
                # 对一个常量进行混淆
                const_index = random.randint(0, have_const_code-1)
                count_index = 0 # 计算遇到过多少个code对象，这个值在跳转之前会被转换成code对象的下标
                for index, code_obj in enumerate(self.co_consts):
                    if iscode(code_obj):
                        if const_index == count_index:
                            count_index = index
                            break
                        count_index += 1
                o = self.__class__(self.co_consts[count_index])
                o.obfuscate(o_func)
                self.co_consts[count_index] = o.get_code()
                return
        else:
            self.__obfuscate(o_func)


class PycFileObfuscate():
    """
    pyc文件的混淆类
    """
    def __init__(self, pycfile):
        self.pycfile = pycfile
        f = open(self.pycfile, "rb")
        self.magic = f.read(4)
        self.time = struct.unpack("<I", f.read(4))[0]
        self.code = CodeObfuscate(marshal.loads(f.read()))
        f.close()

    def write(self, path="", src_info=False):
        '''
        写pyc文件到本地磁盘，时间戳默认为当前时间
        :param path: 文件路径， 默认写回pyc文件的路径
        :param src_info: 是否是原本的信息写入到文件中， 默认写入当前信息
        :return: 无返回值， 写入默认回覆盖文件
        '''
        if not path:
            path = self.pycfile
        if src_info:
            self.code.write(path, self.magic, self.time)
        else:
            self.code.write(path, importlib.util.MAGIC_NUMBER, int(time.time()))

    def obfuscate(self, o_func):
        """
        混淆器
        :param o_func:混淆器函数
        :return:
        """
        self.code.obfuscate(o_func)


class PyFileObfuscate(PycFileObfuscate):
    """
    code obfuscate class
    """

    def __init__(self, file):
        """
        构造方法
        :param file: .py文件路径
        """
        self.file = file

        # 对文件进行编译
        if not os.path.exists(self.file+'c'):
            py_compile.compile(self.file)
        PycFileObfuscate.__init__(self, self.file + 'c')
