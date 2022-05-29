import time
import threading
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *

import time
import random
from threading import Thread, current_thread
from queue import Queue, Empty

foods = ("蒸羊羔","蒸熊掌","蒸鹿尾儿","烧花鸭","烧雏鸡","烧子鹅",
        "卤猪","卤鸭","酱鸡","腊肉","松花","小肚儿","晾肉","香肠",
        "什锦苏盘",)  # 食物列表
def producer(queue):  # 生产者
    print('[{}]厨师来了'.format(current_thread().name))
    # current_thread()返回一个Thread对象，其有一个name属性，表示线程的名字
    global foods
    for i in range(10):  # 上十道菜，每道菜加工0.8s
        food = random.choice(foods)
        print('[{}]正在加工{}中.....'.format(current_thread().name,food))
        time.sleep(0.8)
        print('[{}]上菜了...'.format(current_thread().name))
        queue.put(food)


def consumer(queue):
    print('[{}]客人来了'.format(current_thread().name))
    while True:  # 每道菜吃0.5s，等上菜的耐心是0.5s
        try:
            food = queue.get(timeout=0.5)
            print('[{}]正在享用美食:{}'.format(current_thread().name,food))
            time.sleep(0.5)
        except Empty:  # get不到会抛出Empty
            print("没菜吃了，[{}]走了".format(current_thread().name))
            break


if __name__ == '__main__':
    queue = Queue()
    pds = []  # 生产者列表
    csm = []  # 消费者列表
    for i in range(4):
        t = Thread(target=producer, args=(queue,))  # 由于参数是元组，所以末尾加逗号
        t.start()
        pds.append(t)
    time.sleep(1)
    for i in range(2):
        t = Thread(target=consumer, args=(queue,))
        t.start()
        csm.append(t)