from os import *
from os.path import isdir

files = []

def func(dir):
    for v in listdir(dir):
        if (isdir(dir + "/" + v)):
            dir += "/"
            func(dir=dir + "/" + v)
        else:
            files.append(dir + "/" + v)


if __name__ == "__main__":
    func("C:/Users/yoavo/Documents/GitHub/RustyDolphin/RustyDolphin/src")

    for file in files:
        f = __builtins__.open(file, "r")
        print(file.split("/")[-1] + ":\n" + f.read() + "\n\n")
