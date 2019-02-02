from flask import Flask, request
from threading import Thread
from argparse import ArgumentParser
import random
import requests
import time


app = Flask(__name__)


def main():
    parser = ArgumentParser()
    parser.add_argument('--porta', type=int, help="Port number to run the Flask application on")
    parser.add_argument('--portb', type=int, help="Port number for peer")
    args = parser.parse_args()

    app.port_b = args.portb
    app.run(host='localhost', port=args.porta, debug=True)


def diffie_hellman_algo():
    app.prime = generate_prime(100)
    app.g = find_primitive_root(app.prime)
    app.n = random.randint(2, app.prime)
    return


def generate_prime(range_max):
    primes = []
    for x in range(3, range_max):
        found = True
        for y in range(2, x):
            if x % y == 0:
                found = False
                break

        if found:
            primes.append(x)

    ran = random.randint(1, primes.__len__() - 1)
    return primes[ran]


def find_primitive_root(prime):
    found_g = []
    for a in range(1, prime):
        my_list = []
        for x in range(1, prime + 1):
            my_list.append(pow(a, x) % prime)
        my_list = list(set(my_list))

        if my_list.__len__() != prime - 1:
            continue

        found_g.append(a)

    ran = random.randint(1, found_g.__len__() - 1)
    return found_g[ran]


def send_request(url, is_get, data):
    time.sleep(0.01)
    if is_get:
        requests.get(url=url)
    else:
        requests.post(url=url, data=data)
    return


@app.route('/init', methods=['GET'])
def initiate():
    diffie_hellman_algo()
    a = pow(app.g, app.n) % app.prime
    url = str.format('http://127.0.0.1:{0}/exchange/1?p={1}&g={2}&A={3}', app.port_b, app.prime, app.g, a)
    Thread(target=send_request, args=(url, True, None,)).start()
    return ''


@app.route('/exchange/1', methods=['GET'])
def exchange1():
    prime = int(request.args.get('p'))
    g = int(request.args.get('g'))
    n = random.randint(2, prime)
    app.s_key = pow(int(request.args.get('A')), n) % prime

    b = pow(g, n) % prime
    url = str.format('http://127.0.0.1:{0}/exchange/2?B={1}', app.port_b, b)
    Thread(target=send_request, args=(url, True, None,)).start()
    print 'Secret Bob:', app.s_key, '(Hide it in RT)'
    return ''


@app.route('/exchange/2', methods=['GET'])
def exchange2():
    app.s_key = pow(int(request.args.get('B')), app.n) % app.prime
    print 'Secret Alice:', app.s_key, '(Hide it in RT)'
    return ''


@app.route('/send_plain_message', methods=['POST'])
def send_plain_message():
    url = str.format('http://127.0.0.1:{0}/receive_secure_message', app.port_b)
    cipher_data = encrypt_message(request.data, app.s_key)
    response = str(requests.post(url=url, data=cipher_data).content)
    print 'Encrypted message:', response
    print 'Decrypted message:', decrypt_message(response, app.s_key)
    return ''


@app.route('/receive_secure_message', methods=['POST'])
def receive_secure_message():
    plain_text = decrypt_message(request.data, app.s_key)
    print 'Encrypted message:', request.data
    print 'Decrypted message:', plain_text
    plain_text = str.format('{0}{1}', plain_text, 'ack')
    return encrypt_message(plain_text, app.s_key)


def encrypt_message(m, secret_k):
    return ''.join(format(ord(x) ^ secret_k, 'c') for x in m)


def decrypt_message(m, secret_k):
    return encrypt_message(m, secret_k)


if __name__ == '__main__':
    main()
