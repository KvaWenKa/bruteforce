import time
import hashlib
import multiprocessing
#import threading

alp = "abcdefghijklmnopqrstuvwxyz"
len_password = 5
sha256_hashes = ["1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
          "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
          "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f"]
md5_hashes = ["8b61c11eb8baedd53d2e99d1a01fa7bb",
          "286a03842af6933d393d492880934fb5",
          "2fd2f6d846b1664a8b79b2f4ead806eb"]

def gen_password(alphabet, len_pass, num):
    password = ""
    for i in range(len_pass):
        password += alphabet[num % len(alphabet)]
        num = num // len(alphabet)
    return password[::-1]

def bf_sha256(id_thr,hashes, first_pass, end_pass):
    for i in range(first_pass,end_pass):
        password = gen_password(alp, len_password, i)
        sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if sha256_hash in hashes:
            print(f"    Поток {id_thr}: Подобран пароль '{password}' для хеша {sha256_hash}")

def bf_md5(id_thr,hashes, first_pass, end_pass):
    for i in range(first_pass, end_pass):
        password = gen_password(alp, len_password, i)
        md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
        if md5_hash in hashes:
            print(f"    Поток {id_thr}: Подобран пароль '{password}' для хеша {md5_hash}")

def bruteforce_hash(alg_hash, hashes, len_alp, len_pass):
    print(f"BF: Алгоритм хеширования '{alg_hash}' Кол-во {len(hashes)} Длинна пароля {len_pass}")
    count_pass = len_alp**len_pass-1
    count_threads = int(input(f"Количество потоков для обработки(от 1 до {multiprocessing.cpu_count()}):"))
    if count_threads > multiprocessing.cpu_count():
        print("Error")
        return
    start_time = time.perf_counter()
    if count_threads < 1: count_threads = 1
    # Распределение паролей по потокам
    count_pass_thread = count_pass // count_threads
    threads = []
    start = 0
    for id in range(count_threads):
        if alg_hash == 'sha256':
            thr = multiprocessing.Process(target=bf_sha256, args=(id, hashes, start, start+count_pass_thread if id != count_threads-1 else count_pass))
        elif alg_hash == 'md5':
            thr = multiprocessing.Process(target=bf_md5, args=(id, hashes, start, start+count_pass_thread if id != count_threads-1 else count_pass))
        threads.append(thr)
        thr.start()
        start += count_pass_thread

    for thread in threads:
        thread.join()
    print(f"Время выполнения: {time.perf_counter() - start_time}.")

if __name__ == '__main__':
    bruteforce_hash('sha256', sha256_hashes, len(alp), len_password)
    bruteforce_hash('md5', md5_hashes, len(alp), len_password)
