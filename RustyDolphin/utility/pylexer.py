from os import listdir
from os.path import isdir

import pygments
from pygments.formatters import *
from pygments.lexers import PythonLexer

files = []


def func(dir):
    for v in listdir(dir):
        if (isdir(dir + "/" + v)):
            dir += "/"
            func(dir=dir + "/" + v)
        else:
            files.append(dir + "/" + v)


if __name__ == "__main__":
    func("PUT YOUR PROGRAM DIR HERE")
    rtf_code = ""
    code = ""

    for file in files:
        f = open(file, "r")
        name = file.split("/")[-1]
        code += f"//{name}\n\n" + f.read() + "\n\n"

    with open('code.rtf', 'w') as f:
        f.write(pygments.highlight(code, PythonLexer(), RtfFormatter()))
