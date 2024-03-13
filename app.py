from flask import Flask, render_template, request
import numpy as np
import binascii

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('crypto.html', result=None)

@app.route('/process_input', methods=['POST'])
def process_input():
    user_input = request.form['user_input']
    key_input = request.form['key_input']
    cypher_input = request.form['user_input']
    algo_input = request.form['algo_input']
    processed_result = process_input_data(user_input)
    
    if algo_input == "OTP":
        key1 = generate_random_key(len(user_input))
        processed_result1 = process_input_data1(key1)
        processed_result2 = process_input_data2(user_input, key1, algo_input)
    else:
        processed_result1 = process_input_data1(key_input)
        processed_result2 = process_input_data2(user_input, key_input, algo_input)
    processed_result3 = process_input_data3(algo_input)
    return render_template('crypto.html', result = processed_result, result1 = processed_result1, result2 = processed_result2, result3 = processed_result3) 

def process_input_data(input_data):
    return input_data

def process_input_data1(input_data):
    return input_data

def process_input_data2(plaintext, key, algo):
    if algo == "Caesar cipher":
        encrypt_data = Caesar_cipher(plaintext, key)
    elif algo == "Monoalphabetic":
        encrypt_data = monoalphabetic(plaintext, key)
    elif algo == "Polyalphabetic":
        encrypt_data = Polyalphabetic(plaintext, key)
    elif algo == "Hill cipher":
        encrypt_data = hill_cipher(plaintext, key)
    elif algo == "Playfair":
        encrypt_data = playfair(plaintext, key)
    elif algo == "OTP":
        encrypt_data = otp(plaintext, key)
    elif algo == "Rail fence":
        encrypt_data = rail_fence(plaintext, key)
    elif algo == "Columnar":
        encrypt_data = columnar(plaintext, key)
    elif algo == "DES":
        random.seed()
        key2 = random.getrandbits(56)
        encrypt_data = encrypt(plaintext, key2)
    elif algo == "AES":
        key2 = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
        #plaintext1 = binascii.hexlify(plaintext.encode())
        #plaintext2 = bytearray.fromhex(plaintext)
        #plaintext2 = plaintext.encode('utf-8')
        plaintext1 = text_to_hex(plaintext)
        plaintext2 = bytearray.fromhex(plaintext1)
        encrypt_data2 = aes_encryption(plaintext2, key2)
        encrypt_data = int.from_bytes(encrypt_data2, byteorder='big')
    return encrypt_data

def process_input_data3(input_data):
   return input_data

def Caesar_cipher(plaintext, key):
    
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            shift = ord('A') if char.isupper() else ord('a')
            shifted_char = chr((ord(char) - shift + int(key)) % 26 + shift)
            ciphertext += shifted_char
        else:
            ciphertext += char  
    return ciphertext

def monoalphabetic(plaintext, key):
    mapping = {chr(i + 65): key[i].upper() for i in range(26)}
    mapping.update({chr(i + 97): key[i].lower() for i in range(26)})
    
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            ciphertext += mapping[char]
        else:
            ciphertext += char
    return ciphertext

def Polyalphabetic(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    
    repeated_key = key * (len(plaintext) // len(key)) + key[:len(plaintext) % len(key)]
    
    ciphertext = ''
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            shifted_char = chr(((ord(plaintext[i]) - 65) + (ord(repeated_key[i]) - 65)) % 26 + 65)
            ciphertext += shifted_char
        else:
            ciphertext += plaintext[i]
    return ciphertext


def hill_cipher(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()

    key_size = int(np.sqrt(len(key)))
    key_matrix = np.array([ord(char) - 65 for char in key]).reshape(key_size, key_size)

    while len(plaintext) % key_size != 0:
        plaintext += 'X'

    plaintext_matrix = np.array([ord(char) - 65 for char in plaintext]).reshape(-1, key_size)

    ciphertext_matrix = np.dot(plaintext_matrix, key_matrix) % 26

    ciphertext = ''
    for row in ciphertext_matrix:
        for num in row:
            ciphertext += chr(num + 65)
    return ciphertext

def generate_playfair_matrix(key):
    
    key = key.upper().replace('J', 'I')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    
    for letter in key:
        if letter not in matrix:
            matrix.append(letter)
    
    for letter in alphabet:
        if letter not in matrix:
            matrix.append(letter)
    
    playfair_matrix = [matrix[i:i+5] for i in range(0, 25, 5)]
    return playfair_matrix

def playfair(plaintext, key):
    
    playfair_matrix = generate_playfair_matrix(key)
    plaintext = plaintext.upper().replace('J', 'I') 
    ciphertext = ''

    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i+2]
        if len(pair) < 2: 
            pair += 'X'
        
        pos1 = [(r, c) for r in range(5) for c in range(5) if playfair_matrix[r][c] == pair[0]][0]
        pos2 = [(r, c) for r in range(5) for c in range(5) if playfair_matrix[r][c] == pair[1]][0]

        if pos1[0] == pos2[0]:
            ciphertext += playfair_matrix[pos1[0]][(pos1[1] + 1) % 5] + playfair_matrix[pos2[0]][(pos2[1] + 1) % 5]
        elif pos1[1] == pos2[1]:
            ciphertext += playfair_matrix[(pos1[0] + 1) % 5][pos1[1]] + playfair_matrix[(pos2[0] + 1) % 5][pos2[1]]
        else:
            ciphertext += playfair_matrix[pos1[0]][pos2[1]] + playfair_matrix[pos2[0]][pos1[1]]
    
    return ciphertext

import random

def generate_random_key(length):
    
    return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(length))

def otp(plaintext, key):
    
    plaintext = plaintext.upper()
    key = key.upper()
    
    if len(key) != len(plaintext):
        raise ValueError("Key length must be equal to plaintext length")

    ciphertext = ''
    for i in range(len(plaintext)):
        encrypted_char = chr((ord(plaintext[i]) - 65 + ord(key[i]) - 65) % 26 + 65)
        ciphertext += encrypted_char
    return ciphertext

def rail_fence(plaintext, key):
    
    plaintext = plaintext.upper()
    key = int(key)
    
    
    pattern = list(range(key)) + list(range(key-2, 0, -1))
    rails = [''] * key
    
    
    for i, char in enumerate(plaintext):
        rail_index = pattern[i % len(pattern)]
        rails[rail_index] += char
    
    
    ciphertext = ''.join(rails)
    return ciphertext

import math

def columnar(plaintext, key):
    key = key.replace(" ", "").upper()
    
    num_columns = len(key)
   
    num_rows = -(-len(plaintext) // num_columns)  
    
    padded_plaintext = plaintext.ljust(num_columns * num_rows)
    
    
    grid = [list(padded_plaintext[i:i+num_columns]) for i in range(0, len(padded_plaintext), num_columns)]
    
    
    reordered_columns = [column for _, column in sorted(zip(key, zip(*grid)))]
    
    
    ciphertext = ''.join(''.join(column) for column in reordered_columns)
    return ciphertext

import random
def encrypt (plaintext, key):
    nblocks = ((len(plaintext) - 1) >>3)+1
    ciphertext = ""
    
    for block in range(nblocks):
        value = 0
        pos = block << 3
        for i in range(8):
            value = (value<<8)
            if pos + i < len(plaintext):
                value = value | ord(plaintext[pos + i])
                
        des =DES(value, key)
        
        ctext = ""
        for i in range(8):
            letter = des & 0xFF
            ctext = chr(letter) + ctext
            des = des >> 8
        ciphertext += ctext
        
    return ciphertext

def permutate(number, permutation, bits):
    result = 0
    for perm in permutation:
        bit = (number >> (bits - perm)) & 1
        result = (result << 1) | bit
    return result

def rotLeft(key, bits):
    return ((key << 1)&((1<<bits) - 1)) | (key >> (bits - 1))

def rotRight(key, bits):
    return ((key & 1) << (bits -1)) | (key >> 1)

def sboxFun(number, fun):
    row = ((number & 0x20) >> 4) | (number & 1)
    col = (number >> 1) & 0xF
    return fun[row][col]

def DES(number, key, invertSch = False):
    firstPerm = [58, 50, 42, 34, 26, 18, 10, 2,
                 60, 52, 44, 36, 28, 20, 12, 4,
                 62, 54, 46, 38, 30, 22, 14, 6,
                 64, 56, 48, 40, 32, 24, 16, 8,
                 57, 49, 41, 33, 25, 17, 9, 1,
                 59, 51, 43, 35, 27, 19, 11, 3,
                 61, 53, 45, 37, 29, 21, 13, 5,
                 63, 55, 47, 39, 31, 23, 15, 7]
    expansionFun = [32, 1, 2, 3, 4, 5, 
                    4, 5, 6, 7, 8, 9, 
                    8, 9, 10, 11, 12, 13, 
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25, 
                    24, 25, 26, 27, 28, 29, 
                    28, 29, 30, 31, 32, 1]
    lastPerm = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25]
    pc2Perm = [14, 17, 11, 24, 1, 5,
               3, 28, 15, 6, 21, 10,
               23, 19, 12, 4, 26, 8,
               16, 7, 27, 20, 13, 2,
               41, 52, 31, 37, 47, 55,
               30, 40, 51, 45, 33, 48,
               44, 49, 39, 56, 34, 53,
               46, 42, 50, 36, 29, 32]
    interPerm = [16, 7, 20, 21,
                            29, 12, 28, 17,
                            1, 15, 23, 26,
                            5, 18, 31, 10,
                            2, 8, 24, 14,
                            32, 27, 3, 9,
                            19, 13, 30, 6,
                            22, 11, 4, 25]
    sboxFun1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
    
    number = permutate(number, firstPerm, 64)
    L = number >> 32
    R = number & 0xFFFFFFFF
    
    if invertSch:
        for i in range(16 + 1):
            key = rotLeft(key, 56)
            
    for it in range(16):
        if not invertSch:
            key = rotLeft(key, 56)
        else:
            key = rotLeft(key, 56)
        roundKey = permutate(key, pc2Perm, 56)
        
        expansion = permutate(R, expansionFun, 32)
        
        intnum = roundKey ^ expansion
        
        snum = 0
        for nbox in range(8):
            chunk = (intnum >> (42 - nbox*6)) & 0x3F
            sbox = sboxFun(chunk, sboxFun1)
            snum = (snum << 4) | sbox
            
        inter = permutate(snum, interPerm, 32)
        
        newR = inter ^ L
        L= R
        R = newR
    number = (R<<32) | L
    
    number = permutate(number, lastPerm, 64)
    return number

def printableStr(str):
    pstr = ""
    for c in str:
        if ord(c) in range(32, 127):
            pstr +=c
        else:
            pstr += "."
    return pstr

s_box_string = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76' \
               'ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0' \
               'b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15' \
               '04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75' \
               '09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84' \
               '53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf' \
               'd0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8' \
               '51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2' \
               'cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73' \
               '60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db' \
               'e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79' \
               'e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08' \
               'ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a' \
               '70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e' \
               'e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df' \
               '8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16'.replace(" ", "")


s_box = bytearray.fromhex(s_box_string)


def sub_word(word: [int]) -> bytes:
    substituted_word = bytes(s_box[i] for i in word)
    return substituted_word


def rcon(i: int) -> bytes:
    # From Wikipedia
    rcon_lookup = bytearray.fromhex('01020408102040801b36')
    rcon_value = bytes([rcon_lookup[i-1], 0, 0, 0])
    return rcon_value


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


def rot_word(word: [int]) -> [int]:
    return word[1:] + word[:1]


def key_expansion(key: bytes, nb: int = 4) -> [[[int]]]:

    nk = len(key) // 4

    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  
        nr = 14

    w = state_from_bytes(key)

    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - nk], temp))

    return [w[i*4:(i+1)*4] for i in range(len(w) // 4)]


def add_round_key(state: [[int]], key_schedule: [[[int]]], round: int):
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]


def sub_bytes(state: [[int]]):
    for r in range(len(state)):
        state[r] = [s_box[state[r][c]] for c in range(len(state[0]))]


def shift_rows(state: [[int]]):
    
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


def xtime(a: int) -> int:
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1


def mix_column(col: [int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= all_xor ^ xtime(col[0] ^ col[1])
    col[1] ^= all_xor ^ xtime(col[1] ^ col[2])
    col[2] ^= all_xor ^ xtime(col[2] ^ col[3])
    col[3] ^= all_xor ^ xtime(c_0 ^ col[3])


def mix_columns(state: [[int]]):
    for r in state:
        mix_column(r)


def state_from_bytes(data: bytes) -> [[int]]:
    state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
    return state


def bytes_from_state(state: [[int]]) -> bytes:
    return bytes(state[0] + state[1] + state[2] + state[3])


def aes_encryption(data: bytes, key: bytes) -> bytes:

    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  
        nr = 14

    state = state_from_bytes(data)

    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule, round=0)

    for round in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    cipher = bytes_from_state(state)
    return cipher


def inv_shift_rows(state: [[int]]) -> [[int]]:
    
    state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
    state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
    state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]
    return


inv_s_box_string = '52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb' \
                   '7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb' \
                   '54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e' \
                   '08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25' \
                   '72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92' \
                   '6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84' \
                   '90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06' \
                   'd0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b' \
                   '3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73' \
                   '96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e' \
                   '47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b' \
                   'fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4' \
                   '1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f' \
                   '60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef' \
                   'a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61' \
                   '17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d'.replace(" ", "")

inv_s_box = bytearray.fromhex(inv_s_box_string)


def inv_sub_bytes(state: [[int]]) -> [[int]]:
    for r in range(len(state)):
        state[r] = [inv_s_box[state[r][c]] for c in range(len(state[0]))]


def xtimes_0e(b):
    
    return xtime(xtime(xtime(b) ^ b) ^ b)


def xtimes_0b(b):
    
    return xtime(xtime(xtime(b)) ^ b) ^ b


def xtimes_0d(b):
    
    return xtime(xtime(xtime(b) ^ b)) ^ b


def xtimes_09(b):
    
    return xtime(xtime(xtime(b))) ^ b


def inv_mix_column(col: [int]):
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
    col[0] = xtimes_0e(c_0) ^ xtimes_0b(c_1) ^ xtimes_0d(c_2) ^ xtimes_09(c_3)
    col[1] = xtimes_09(c_0) ^ xtimes_0e(c_1) ^ xtimes_0b(c_2) ^ xtimes_0d(c_3)
    col[2] = xtimes_0d(c_0) ^ xtimes_09(c_1) ^ xtimes_0e(c_2) ^ xtimes_0b(c_3)
    col[3] = xtimes_0b(c_0) ^ xtimes_0d(c_1) ^ xtimes_09(c_2) ^ xtimes_0e(c_3)


def inv_mix_columns(state: [[int]]) -> [[int]]:
    for r in state:
        inv_mix_column(r)


def inv_mix_column_optimized(col: [int]):
    u = xtime(xtime(col[0] ^ col[2]))
    v = xtime(xtime(col[1] ^ col[3]))
    col[0] ^= u
    col[1] ^= v
    col[2] ^= u
    col[3] ^= v


def inv_mix_columns_optimized(state: [[int]]) -> [[int]]:
    for r in state:
        inv_mix_column_optimized(r)
    mix_columns(state)


def aes_decryption(cipher: bytes, key: bytes) -> bytes:

    key_byte_length = len(key)
    key_bit_length = key_byte_length * 8
    nk = key_byte_length // 4

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  
        nr = 14

    state = state_from_bytes(cipher)
    key_schedule = key_expansion(key)
    add_round_key(state, key_schedule, round=nr)

    for round in range(nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, round=0)

    plain = bytes_from_state(state)
    return plain

def text_to_hex(text):
    
    encoded_bytes = text.encode('utf-8')
    
    hex_representation = encoded_bytes.hex()
    return hex_representation

if __name__ == '__main__':
    app.run(debug=True)
