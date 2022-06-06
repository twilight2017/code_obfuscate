# coding:utf-8
from code_obfuscate.obfuscate import PyFileObfuscate, advanced, insert_Identification
from functools import partial

pyf_obfu = PyFileObfuscate("E:/study/python/yunchou/yunchou.py")
for line in range(200):
    pyf_obfu.obfuscate(advanced)
for line in range(100):
    pyf_obfu.obfuscate(partial(insert_Identification, "\r\n\r\n=====================\r\n\r\n测试的字符串\r\n\r\n=======================\r\n\r\n"))

pyf_obfu.write("E:/study/python/yunchou/obfuscate.py")