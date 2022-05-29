from concurrent.futures import ThreadPoolExecutor
import threading
import time

# 定义一个准备作为线程任务的函数
def action(max):
    my_sum = 0
    for i in range(max):
        print(threading.current_thread().name + '  ' + str(i))
        my_sum += i
    return my_sum
# 创建一个包含2条线程的线程池
pool = ThreadPoolExecutor(max_workers=2)
# 向线程池提交一个task, 50会作为action()函数的参数
future1 = pool.submit(action, 50)
# 向线程池再提交一个task, 100会作为action()函数的参数
future2 = pool.submit(action, 100)
# 判断future1代表的任务是否结束
print(future1.done())
time.sleep(3)
# 判断future2代表的任务是否结束
print(future2.done())
# 查看future1代表的任务返回的结果
print(future1.result())
# 查看future2代表的任务返回的结果
print(future2.result())
# 关闭线程池
pool.shutdown()

# 定义一个准备作为线程任务的函数
def action(max):
    my_sum = 0
    for i in range(max):
        print(threading.current_thread().name + '  ' + str(i))
        my_sum += i
    return my_sum
# 创建一个包含2条线程的线程池
# 线程池支持上下文管理协议，用with可以避免忘记写shutdown
with ThreadPoolExecutor(max_workers=2) as pool:
    # 使用线程执行map计算
    # 后面元组有3个元素，因此程序启动3次线程来执行action函数
    results = pool.map(action, (50, 100, 150))
    print('--------------')
    for r in results:
        print(r)