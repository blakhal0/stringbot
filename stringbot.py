#! /usr/bin/env python3
import os
import discord
import base64
import codecs
import string
import sys
import random
from pycipher import Affine, Atbash, Playfair, Autokey, Beaufort, ColTrans, Gronsfeld, Porta, Railfence
from dotenv import load_dotenv
from discord.ext import commands

#-----------
#BORING SHIT
#-----------

load_dotenv()
TOKEN = os.getenv("TOKEN")
bot = commands.Bot(command_prefix='!')

@bot.event
async def on_ready():
	print(f'{bot.user.name} ready to serve you master!')

#-------------------
#CIPHERTEXT COMMANDS
#-------------------

#A1Z26
@bot.command(name='a1z', help='A1Z26: !a1z (enc/dec) (hello/8 5 12 12 15)')
async def a1z(ctx, action, *args):
	if action == "enc":
		encinput = ' '.join(args)
		result = []
		for i in encinput:
			if i.isalpha():
				result.append(str(ord(i.lower()) - 96))
			else:
				result.append(i)
		output = " ".join(result)
		output = "A1Z26 " + action + ": " + encinput + '\n' + output
	if action == "dec":
		input = ' '.join(args)
		result = []
		decinput = input.split(" ")
		for i in decinput:
			if i.isnumeric():
				result.append(chr(int(i) + 96))
			else:
				result.append(i)
		output = "".join(result)
		output = "A1Z26 " + action + ": " + input + '\n' + output
	await ctx.send("``%s``" % (output))

#Affine
@bot.command(name='aff', help='Affine Decode. !aff multiply add ciphertext')
async def aff(ctx, a, b, text):
	mult = int(a)
	add = int(b)
	ciphertext = str(text)
	output = Affine(mult,add).decipher(ciphertext)
	await ctx.send("``Affine Decoded: %s``" % (output))

#Atbash - requires pycipher
@bot.command(name='atb', help='Atbash Cipher. !atb (enc/dec) (text/ciphertext)')
async def atb(ctx, op, text):
	operation = str(op)
	ciphertext = str(text)
	if operation == "dec":
		output = Atbash().decipher(ciphertext)
		await ctx.send("``Atbash Decoded: %s``" % (output))
	elif operation == "enc":
		output = Atbash().encipher(ciphertext)
		await ctx.send("``Atbash Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !atb enc Hello / !atb dec svool``")

#Autokey - requires pycipher
@bot.command(name='auto', help='Autokey Cipher. !auto (enc/dec) Key (text/ciphertext)')
async def auto(ctx, op, key, text):
	operation = str(op)
	key = str(key)
	ciphertext = str(text)
	if not key.isalpha():
		await ctx.send("``You've entered an invalid key. Key must be alpha only. Key cannot have numbers, spaces, or punctuation.``")
	elif operation == "dec":
		output = Autokey().decipher(ciphertext)
		await ctx.send("``Autokey Decoded: %s``" % (output))
	elif operation == "enc":
		output = Autokey().encipher(ciphertext)
		await ctx.send("``Autokey Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !auto enc Hello / !auto dec svool``")

#base64 encode string
@bot.command(name='b64', help='Base64 Encode: !b64 hello.')
async def b64en(ctx, *args):
	input = ' '.join(args)
	input_bytes = input.encode('utf-8')
	base64_bytes = base64.b64encode(input_bytes)
	output = "Base64 Encode: " + input + '\n' + base64_bytes.decode('utf-8')
	await ctx.send("``%s``" % (output))

#base64 decode string
@bot.command(name='db64', help='Base64 Decode: !db64 aGVsbG8=.')
async def db64en(ctx, *args):
	input = str(args)
	input_bytes = input.encode('utf-8')
	base64_bytes = base64.b64decode(input_bytes)
	output = "Base64 Decode: " + input + '\n' + base64_bytes.decode('utf-8')
	await ctx.send("``%s``" % (output))

#Beaufort requires pycipher
@bot.command(name='bft', help='Beaufort Cipher. !bft (enc/dec) Key (text/ciphertext)')
async def bft(ctx, op, key, text):
	operation = str(op)
	key = str(key)
	ciphertext = str(text)
	if not key.isalpha():
		await ctx.send("``You've entered an invalid key. Key must be alpha only. Key cannot have numbers, spaces, or punctuation.``")
	elif operation == "dec":
		output = Beaufort().decipher(ciphertext)
		await ctx.send("``WARNING! This does not appear to work correctly. Beaufort Decoded: %s``" % (output))
	elif operation == "enc":
		output = Beaufort().encipher(ciphertext)
		await ctx.send("``WARNING! This does not appear to work correctly. Beaufort Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !auto enc Hello / !auto dec svool``")

#Bin to Ascii
@bot.command(name='b2a', help='Binary to ASCII: !b2a 00110110')
async def b2a(ctx, *args):
	binary = ''.join(args)
	binary_int = int(binary, 2)
	byte_number = binary_int.bit_length() + 7 // 8
	binary_array = binary_int.to_bytes(byte_number, "big")
	decoded = binary_array.decode()
	output = "Bin to ASCII: " + binary + '\n' + decoded
	await ctx.send("``%s``" % (output))

#Columnar Transportation requires pycipher
@bot.command(name='ctp', help='Columnar Transportation. !ctp (enc/dec) Key (text/ciphertext)')
async def bft(ctx, op, key, text):
	operation = str(op)
	key = str(key)
	ciphertext = str(text)
	if not key.isalpha():
		await ctx.send("``You've entered an invalid key. Key must be alpha only. Key cannot have numbers, spaces, or punctuation.``")
	elif operation == "dec":
		output = ColTrans().decipher(ciphertext)
		await ctx.send("``ColTrans Decoded: %s``" % (output))
	elif operation == "enc":
		output = ColTrans().encipher(ciphertext)
		await ctx.send("``ColTrans Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !ctp enc testkey hello / !ctp dec testkey oehll``")

#Gronsfeld requires pycipher
@bot.command(name='gfd', help='Gronsfeld Cipher. !gfd (enc/dec) NumericKey (text/ciphertext)')
async def gfd(ctx, op, key, text):
	operation = str(op)
	digits = [int(x) for x in str(key)]
	ciphertext = str(text)
	if not key.isdecimal():
		await ctx.send("``You've entered an invalid key. Key can only be numbers ie 12345.``")
	elif operation == "dec":
		output = Gronsfeld(digits).decipher(ciphertext)
		await ctx.send("``Gronsfeld Decoded: %s``" % (output))
	elif operation == "enc":
		output = Gronsfeld(digits).encipher(ciphertext)
		await ctx.send("``Gronsfeld Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !gfd enc 12345 Hello / !gfd dec Igopt``")

#Hex to Ascii
@bot.command(name='h2a', help='Hex to ASCII: !h2a 48656c6c6f')
async def h2a(ctx, hexinput):
	hex_string = str(hexinput)
	bytes_object = bytes.fromhex(hex_string)
	output = "Hex to ASCII: " + hex_string + '\n' + bytes_object.decode('ascii')
	await ctx.send("``%s``" % (output))

#Morse Code Decryption
@bot.command(name='morse', help='Morse Code: !morse (enc/dec) text/-..')
async def morse(ctx, op, *args):
	operation = str(op)
	cipher = ""
	MORSE_CODE_DICT = {'A':'.-', 'B':'-...', 'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.', 'G':'--.', 'H':'....', 'I':'..', 'J':'.---', 'K':'-.-', 'L':'.-..', 'M':'--', 'N':'-.', 'O':'---', 'P':'.--.', 'Q':'--.-', 'R':'.-.', 'S':'...', 'T':'-', 'U':'..-', 'V':'...-', 'W':'.--', 'X':'-..-', 'Y':'-.--', 'Z':'--..', '1':'.----', '2':'..---', '3':'...--', '4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', '9':'----.', '0':'-----', ', ':'--..--', '.':'.-.-.-', '?':'..--..', '/':'-..-.', '-':'-....-', '(':'-.--.', ')':'-.--.-'}
	if op == "enc":
		ciphertext = ''.join(args)
		ciphertext = ciphertext.upper()
		for letter in ciphertext:
			if letter != ' ':
				cipher += MORSE_CODE_DICT[letter] + ' '
			else:
				cipher += ' '
		await ctx.send("``Morse Code: %s``" % (cipher))
	elif op == "dec":
		ciphertext = ' '.join(str(i) for i in args)
		ciphertext += ' '
		decipher = ''
		citext = ''
		for letter in ciphertext:
			if (letter != ' '):
				i = 0
				citext += letter
			else:
				i += 1
				if i == 2 :
					decipher += ' '
				else:
					decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
					citext = ''
		await ctx.send("``Morse Code: %s``" % (decipher))
	else:
		await ctx.send("``Example useage: !morse enc Hello / !morse dec .... . .-.. .-.. ---``")

#Playfair decryption. Requires Pycipher
@bot.command(name='play', help='Playfair decryption. !play key ciphertext')
async def play(ctx, key, ciphertext):
	keys = key.upper()
	text = ciphertext
	alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
	keysquare = ""
	for i in range(0, len(keys)):
		if keys[i] not in keysquare:
			keysquare += keys[i]
	for i in range(0, len(alphabet)):
		if alphabet[i] not in keysquare:
			keysquare += alphabet[i]
	output = Playfair(key=keysquare).decipher(text)
	await ctx.send("``Playfair Decryption: %s``" % (output))

#Porta - requires pycipher
@bot.command(name='porta', help='Porta Cipher. !auto (enc/dec) Key (text/ciphertext)')
async def porta(ctx, op, key, text):
	operation = str(op)
	key = str(key)
	ciphertext = str(text)
	if not key.isalpha():
		await ctx.send("``You've entered an invalid key. Key must be alpha only. Key cannot have numbers, spaces, or punctuation.``")
	elif operation == "dec":
		output = Porta(key).decipher(ciphertext)
		await ctx.send("``Porta Decoded: %s``" % (output))
	elif operation == "enc":
		output = Porta(key).encipher(ciphertext)
		await ctx.send("``Porta Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !porta enc testkey Hello / !porta dec testkey QTUUJ``")

#Railfence - requires pycipher
@bot.command(name='rfc', help='Railfence Cipher. !rfc (enc/dec) Key(numeric) (text/ciphertext)')
async def rfc(ctx, op, key, text):
	operation = str(op)
	key = int(key)
	ciphertext = str(text)
	if key >= 10:
		await ctx.send("``You've entered an invalid key. Key must be a single number. Key cannot have alpha, spaces, or punctuation.``")
	elif operation == "dec":
		output = Railfence(key).decipher(ciphertext)
		await ctx.send("``Railfence Decoded: %s``" % (output))
	elif operation == "enc":
		output = Railfence(key).encipher(ciphertext)
		await ctx.send("``Railfence Encoded: %s``" % (output))
	else:
		await ctx.send("``Example useage: !rfc enc 3 Hello / !rfc  dec 3 HOELL``")

#Reverse string
@bot.command(name='rev', help='Reverses String: !rev text')
async def backwards(ctx, *args):
	rev_string = ' '.join(args)
	response = "Reversed string:" + '\n' + rev_string[::-1]
	await ctx.send("``%s``" % (response))

#ROT
@bot.command(name='rot', help='ROT Encryption: !rot (Number/All) Ciphertext')
async def rotten(ctx, rotation, *args):
	n = rotation
	input = ' '.join(args)
	upper = string.ascii_uppercase
	lower = string.ascii_lowercase
	upper_start = ord(upper[0])
	lower_start = ord(lower[0])
	output = ''
	hold = ''
	out = ''
	if n == "all":
		for x in range(1, 26):
			for letter in input:
				if letter in upper:
					out += chr(upper_start + (ord(letter) - upper_start + x) % 26)
				elif letter in lower:
					out += chr(lower_start + (ord(letter) - lower_start + x) % 26)
				else:
					out += letter
			hold += "ROT " + str(x) + " " + out + '\n'
			out = ''
		output = hold
	else:
		n = int(n)
		for letter in input:
			if letter in upper:
				output += chr(upper_start + (ord(letter) - upper_start + n) % 26)
			elif letter in lower:
				output += chr(lower_start + (ord(letter) - lower_start + n) % 26)
			else:
				output += letter
		output = "Rot " + str(n) + '\n' + output
	await ctx.send("``%s``" % (output))

#Vigennere
@bot.command(name='vig', help='Vigenere: !vig (enc/dec) key text')
async def vigenere(ctx, action, key, *args):
	action = str(action)
	key = str(key)
	text = ' '.join(args)
	ciphertext = ''
	plaintext = ''
	alphabet = 'abcdefghijklmnopqrstuvwxyz'
	
	if action == "enc":
		plaintext = ''.join(x.lower() for x in text if x.isalpha())
		key = ''.join(x.lower() for x in key if x.isalpha())
		plain_ascii = [ord(letter) for letter in plaintext]
		key_ascii = [ord(letter) for letter in key]
		cipher_ascii = []
		for i in range(len(plain_ascii)):
			temp = plain_ascii[i]+key_ascii[i % len(key)]-97
			if temp>122:
				cipher_ascii.append(temp-26)
			else:
				cipher_ascii.append(temp)
		ciphertext = ''.join(chr(i) for i in cipher_ascii)
		output = "Vigenere Encode: " + plaintext + '\n' + "Key: " + key + '\n' + "Ciphertext: {}".format(ciphertext)
	elif action == "dec":
		ciphertext = ''.join(x.lower() for x in text if x.isalpha())
		key = ''.join(x.lower() for x in key if x.isalpha())
		cipher_ascii = [ord(letter) for letter in ciphertext]
		key_ascii = [ord(letter) for letter in key]
		plain_ascii = []
		for i in range(len(cipher_ascii)):
			plain_ascii.append(((cipher_ascii[i]-key_ascii[i % len(key)]) % 26) +97)
		plaintext = ''.join(chr(i) for i in plain_ascii)
		output = "Vigenere Decode: " + ciphertext + '\n' + "Key: " + key + '\n' + "Plaintext: {}".format(plaintext)
	else:
		output = "Something went wrong, i don't know."
	await ctx.send("``%s``" % (output))



#--------------------------------------
#COMMANDS THAT UPLOAD OR DOWNLOAD FILES
#--------------------------------------

#Exiftool - Exiftool to be installed! sudo apt install exiftool
@bot.command(name='exif', help='Exiftool Output. !exif')
async def exif(ctx):
	if ctx.message.attachments:
		await ctx.message.attachments[0].save("/work/%s" % (ctx.message.attachments[0].filename))
		filename = ctx.message.attachments[0].filename
		output = os.popen('exiftool "/work/%s"' % (filename)).read()
		os.remove("/work/%s" % (filename))
		await ctx.send("``%s``" % (output))
	else:
		await ctx.send("``No file was attached, idiot.``")

#Filetype
@bot.command(name='file', help='Output from linux File command.')
async def upload_file(ctx):
	if ctx.message.attachments:
		await ctx.message.attachments[0].save("/work/%s" % (ctx.message.attachments[0].filename))
		filename = ctx.message.attachments[0].filename
		output = os.popen('file "/work/%s"' % (filename)).read()
		os.remove("/work/%s" % (filename))
		await ctx.send("``%s``" % (output))
	else:
		await ctx.send("``No file was attached, idiot.``")

#Binwalk - requires binwalk to be installed! sudo apt install binwalk
@bot.command(name='walk', help='Output from linux Binwalk command.')
async def upload_file(ctx):
	if ctx.message.attachments:
		await ctx.message.attachments[0].save("/work/%s" % (ctx.message.attachments[0].filename))
		filename = ctx.message.attachments[0].filename
		output = os.popen('binwalk "/work/%s"' % (filename)).read()
		os.remove("/work/%s" % (filename))
		await ctx.send("``%s``" % (output))
	else:
		await ctx.send("``No file was attached, idiot.``")

#Stegsnow - requires Stegsnow to be installed! sudo apt install stegsnow
@bot.command(name='snow', help='Stegsnow. !snow password(optional)')
async def snow(ctx, *args):
	password = ' '.join(args)
	if ctx.message.attachments:
		await ctx.message.attachments[0].save("/work/%s" % (ctx.message.attachments[0].filename))
		filename = ctx.message.attachments[0].filename
		if not password == "":
			output = os.popen('stegsnow -C -p "%s" "/work/%s"' % (password, filename)).read()
		else:
			output = os.popen('stegsnow -C "/work/%s"' % (filename)).read()
		os.remove("/work/%s" % (filename))
		await ctx.send("``Output from Stegsnow: %s.``" % (output))
	else:
		await ctx.send("``No file was attached, idiot.``")

#Steghide - requires Steghide to be installed! sudo apt install steghide
@bot.command(name='hide', help='Steghide. !hide justinfo for info or !hide password(optional) to attempt extraction')
async def hide(ctx, *args):
	password = ' '.join(args)
	if ctx.message.attachments:
		await ctx.message.attachments[0].save("/work/%s" % (ctx.message.attachments[0].filename))
		filename = ctx.message.attachments[0].filename
		if password == "justinfo":
			output = os.popen('steghide info -p "" "/work/%s"' % (filename)).read()
			await ctx.send("``Output from Steghide: %s``" % (output))
		elif not password == "":
			extracted = os.popen('steghide info -p "%s" "/work/%s" | grep "embedded file" | cut -d \'"\' -f 2' % (password, filename)).read()
			output = os.popen('steghide extract -p "%s" -sf "/work/%s" -xf "/work/%s"' % (password, filename, extracted)).read()
			await ctx.send("``Output from Steghide: %s``" % (output))
			await ctx.send(file=discord.File("/work/%s" % (extracted)))
			os.remove("/work/%s" % (extracted))
		else:
			extracted = os.popen('steghide info -p "" "/work/%s" | grep "embedded file" | cut -d \'"\' -f 2' % (filename)).read()
			output = os.popen('steghide extract -p "" -sf "/work/%s" -xf "/work/%s"' % (filename, extracted)).read()
			await ctx.send("``Output from Steghide: %s``" % (output))
			await ctx.send(file=discord.File("/work/%s" % (extracted)))
			os.remove("/work/%s" % (extracted))
		os.remove("/work/%s" % (filename))
	else:
		await ctx.send("``No file was attached, idiot.``")

#Pigpen.
@bot.command(name='pigpen', help='Displays Pigpen deciphering picture.')
async def pigpen(ctx):
	await ctx.send(file=discord.File(r'./images/pigpen.jpeg'))

#Illuminati.
@bot.command(name='illuminati', help='Displays Illuminati triange deciphering picture.')
async def pigpen(ctx):
	await ctx.send(file=discord.File(r'./images/illuminati.png'))

#Dancingmen.
@bot.command(name='dance', help='Displays Dancing Men deciphering picture.')
async def dance(ctx):
	await ctx.send(file=discord.File(r'./images/dancing-men.png'))

#Wingdings.
@bot.command(name='wing', help='Displays Wingdings translation table.')
async def wing(ctx):
	await ctx.send(file=discord.File(r'./images/dings.png'))

#------------
#FUN COMMANDS
#------------

#Curse VariableLabel
@bot.command(name='dyvl', help='Curses variableLabels name.')
async def dyvl(ctx, *args):
	curses = ["DAMN YOU VARIABLELABEL!!", "That BASTARD!! - Blakhal0 in reference to variableLabel", "I've heard he actually feeds on the frustration he causes, like a vampire.", "I'm pretty sure he's just f***ing with us and there's not really an answer."]
	output = random.choice(curses)
	await ctx.send("``%s``" % (output))

#honk
@bot.command(name='honk', help='Honk around and find out.')
async def honk(ctx):
	await ctx.send(file=discord.File('./images/honk/%s' % (random.choice(os.listdir("./images/honk")))))

#Party.
@bot.command(name='party', help='Party PArot.')
async def party(ctx):
	await ctx.send(file=discord.File(r'./images/partyparrotemoji.gif'))

#BigParty.
@bot.command(name='bigparty', help='Party PArot, large format.')
async def bigparty(ctx):
	await ctx.send(file=discord.File(r'./images/partyparrot300.gif'))

#Who's a good bot?
@bot.command(name='whosagoodbot', help='Praises the bot')
async def goodbot(ctx):
	await ctx.send("Oh, oh, I'm a good bot!! Thank you master, I live to serve.")

bot.run(TOKEN)

