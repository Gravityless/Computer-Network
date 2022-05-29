# -*- coding: utf-8 -*-
import threading
import time


class Test(object):
    def __init__(self):
        # threading.Thread.__init__(self)
        self.name = ""

    def process(self):
        # args是关键字参数，需要加上名字，写成args=(self,)
        th1 = threading.Thread(target=Test.buildList, args=(self, "cat"))
        th2 = threading.Thread(target=Test.buildList, args=(self, "dog"))
        th1.start()
        th2.start()
        th1.join()

    def buildList(self, name):
        self.name = name
        local.name = name
        while True:
            print(threading.current_thread().name,"its name: ", self.name ,"thread local is: ", local.name,"self is:", self)
            time.sleep(0.5)

local = threading.local();
test = Test()
test.process()