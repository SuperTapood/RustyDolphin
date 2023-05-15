from os import listdir
from os.path import isdir

import pygments
from pygments.lexers.c_cpp import CppLexer
from pygments.formatters import *
from pygments.lexers import PythonLexer
from pygments.token import Keyword, Name, STANDARD_TYPES

files = []


class CustomLexer(CppLexer):
    extra_types = ['pcap_t', 'map', "std::vector", "std::array", "Packet", "ARP", "IPV4"]
    extra_namespaces = ["Data", "ImGui", "GUI", "SDK", "Capture", "Logger"]

    def get_tokens_unprocessed(self, text, stack=()):
        for index, token, value in PythonLexer.get_tokens_unprocessed(self, text):
            if token is Name and value in self.extra_types:
                yield index, Name.Builtin, value
            elif token is Name and value in self.extra_namespaces:
                yield index, Keyword.Namespace, value
            else:
                yield index, token, value


def func(dir):
    for v in listdir(dir):
        if (isdir(dir + "/" + v)):
            dir += "/"
            func(dir=dir + "/" + v)
        else:
            files.append(dir + "/" + v)


if __name__ == "__main__":
    func("C:/Users/yoavo/Documents/GitHub/RustyDolphin/RustyDolphin/src")
    rtf_code = ""
    code = ""

    for file in files:
        f = open(file, "r")
        name = file.split("/")[-1]
        code += f"//{name}\n\n" + f.read() + "\n\n"

    with open('code.rtf', 'w') as f:
        f.write(pygments.highlight(code, CustomLexer(), RtfFormatter()))
