from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from functools import reduce
from gmpy2 import next_prime
from random import randint


def encrypt(text, key):
	while len(key) < len(text):
		key *= 2
	key = key[:len(text)]
	return long_to_bytes(bytes_to_long(text) ^ bytes_to_long(key))


flag = b'hology4{***********************}'

lyric = b'Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you'
arr = [lyric[i:i+32] for i in range(0, len(lyric), 32)]

for i in range(len(arr)):
	for j in range(randint(0, 2**(i + 2))):
		for k in range(randint(min(i, j), max(i, j))):
            flag = encrypt(flag, arr[i])


factors = [getPrime(512)]
for _ in range(9):
	factors.append(next_prime(factors[-1]))
n = reduce(lambda a, b: a*b, factors)
e = 0x10001
m = bytes_to_long(flag)

c = pow(m, e, n)
print('n =', n)
print('e =', e)
print('c =', c)
