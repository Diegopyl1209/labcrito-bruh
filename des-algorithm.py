

def hex2bin(s):
     binary = bin(int(s, 16))[2:].zfill(len(s)*4)
     return binary

# def string_to_binary(string):
#     # Convert each character to its ASCII code and then to a binary string
#     binary_list = [format(ord(char), '08b') for char in string]
#     # Join the binary strings into a single string
#     binary_string = ''.join(binary_list)
#     # Return the binary string
#     return binary_string
#Binary to hexadecimal conversion


def bin2hex(s):
	 hex_string = hex(int(s, 2))[2:].upper()
	 return hex_string

# Binary to decimal conversion


def bin2dec(binary):
	 decimal = int(binary, 2)
	 return decimal

# Decimal to binary conversion


def dec2bin(num):
	binary = bin(int(num))[2:]
	return binary

#The function performs permutation considering the string it receives,
# the matrix and the number of bits you want to have in the string

def permutation(k, matrix, n):
	new_string = ""
	for i in range(0, n):
		new_string = new_string + k[matrix[i] - 1]
	return new_string

#function that performs shifting according to the amount of bits it receives

def shift_left(k, num_of_shifts):
	s = ""
	for i in range(num_of_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k

# calculating xor of two binary number (strings)
def XOR(a, b):
	after_xor = ""
	for i in range(max(len(a),len(b))):
		if a[i] == b[i]:
			after_xor = after_xor+"0"
		else:
			after_xor = after_xor+"1"
	return after_xor
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
					60, 52, 44, 36, 28, 20, 12, 4,
					62, 54, 46, 38, 30, 22, 14, 6,
					64, 56, 48, 40, 32, 24, 16, 8,
					57, 49, 41, 33, 25, 17, 9, 1,
					59, 51, 43, 35, 27, 19, 11, 3,
					61, 53, 45, 37, 29, 21, 13, 5,
					63, 55, 47, 39, 31, 23, 15, 7]
# D-box Table
d_box_table = [32, 1, 2, 3, 4, 5, 4, 5,
				6, 7, 8, 9, 8, 9, 10, 11,
				12, 13, 12, 13, 14, 15, 16, 17,
				16, 17, 18, 19, 20, 21, 20, 21,
				22, 23, 24, 25, 24, 25, 26, 27,
				28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
per = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

# S-box Table
Sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]




def encrypt(plainText, key_after_round_binary):
	# Table of Position of 64 bits at initial level: Initial Permutation Table
	plainText = hex2bin(plainText)
	# Initial Permutation
	plainText = permutation(plainText, initial_perm, 64)
	# dividing the value to 2 parts of 32 bits.
	# left side (from 0 to 32)
	left = plainText[0:32]
	# right side (from 32 to 64)
	right = plainText[32:64]
	for i in range(0, 16):
		#Expansion from 32 bits to 48 bits (so that we can perform xor in the function)
		new_R0 = permutation(right, d_box_table, 48)

		# XOR key_after_round_binary[i] and R0 after permutation
		after_xor = XOR(new_R0, key_after_round_binary[i])

		# S-box: substituting the value from s-box table by calculating row and column
		after_Sbox_per = ""
		# j is the num of box in Sbox
		for j in range(0, 8):
			#row - first and last
			row = bin2dec(int(after_xor[j * 6] + after_xor[j * 6 + 5]))
			#col - the 4 in the middle
			col = bin2dec(
				int(after_xor[j * 6 + 1] + after_xor[j * 6 + 2] +
					after_xor[j * 6 + 3] + after_xor[j * 6 + 4]))
			val = Sbox[j][row][col]
			after_Sbox_per = after_Sbox_per + dec2bin(val)

		# Straight D-box: After substituting rearranging the bits
		after_Sbox_per = permutation(after_Sbox_per, per, 32)

		# XOR left and the string after_Sbox_per
		result = XOR(left, after_Sbox_per)
		left = result
		# swap without the last time
		if(i != 15):
			left, right = right, left
	# Combination
	combine = left + right

	# final permutation (64 bits):
	cipher_text = permutation(combine, final_perm, 64)
	return cipher_text

value_to_encrypt = input('Which string do you want to encrypt?')
key = input('What is your key?')

# Key generation
# key to binary
key = hex2bin(key)
#print("The key is in binary is:" + key);

# --parity bit drop table
PC_1 = [57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]

# Conversion of the key from 48 bits to 56 bits
key = permutation(key, PC_1, 56)

# Number of bit shifts (1,2,9,16 in 1 , else : 2)
shift_table = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]

# Key- Compression Table : Compression of key from 56 bits to 48 bits
PC_2 = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]


C0 = key[0:28] # left side
D0 = key[28:56] # right side

key_after_pre_binary = []
for i in range(16):
    # Shifting the bits by nth shifts by checking from shift table
    C0 = shift_left(C0, shift_table[i])
    D0 = shift_left(D0, shift_table[i])
    # Unification of C0 with D0
    all_str = C0 + D0
    # Compression of key from 56 to 48 bits ("Transform 1")
    round_key = ""
    for j in PC_2:
        round_key += all_str[j - 1]
    key_after_pre_binary.append(round_key)

print("Encryption")
cipher_text = bin2hex(encrypt(value_to_encrypt, key_after_pre_binary))
print("Cipher Text : ", cipher_text)
print("Decryption")
key_after_pre_binary_revers = key_after_pre_binary[::-1]
text = bin2hex(encrypt(cipher_text, key_after_pre_binary_revers))
print("Plain Text : ", text)





