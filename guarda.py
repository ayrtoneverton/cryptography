import sys, os, hmac, json
from glob import glob
from getopt import getopt
from hashlib import sha256

# variables
storage = '/.guarda'
data = {}

# alerts
alert_example = 'Example: py guarda.py (--hash | --hmac <key>) (-i | -t | -x) [-o <output-file>] <folder>'
alert_encode = 'exactly one of these is required: --hash or --hmac <key>'
alert_command = 'exactly one of these is required: -i, -t or -x'
alert_folder = 'exactly one of these is required: <folder>'
alert_not_dir = 'folder not found: %s'
alert_dir_initialized = 'folder already initialized: %s'
alert_dir_not_initialized = 'folder not initialized: %s'

# arguments values
option_i = option_t = option_x = encode = key = None
output = sys.stdout

# treatment of arguments
try:
	opts, args = getopt(sys.argv[1:], 'o:itx', ['hash', 'hmac='])
	for option, value in opts:
		if option == '--hash':
			if encode:
				raise Exception(alert_encode)
			else:
				encode = lambda key, msg: sha256(msg)
		elif option == '--hmac':
			if encode:
				raise Exception(alert_encode)
			else:
				encode = hmac.new
				key = value.encode()
		elif option == '-i':
			if option_t or option_x:
				raise Exception(alert_command)
			else:
				option_i = True
		elif option == '-t':
			if option_i or option_x:
				raise Exception(alert_command)
			else:
				option_t = True
		elif option == '-x':
			if option_t or option_i:
				raise Exception(alert_command)
			else:
				option_x = True
		elif option == '-o':
			output = open(value, 'w')

	if not encode:
		raise Exception(alert_encode)
	if not (option_i or option_t or option_x):
		raise Exception(alert_command)
	if len(args) != 1:
		raise Exception(alert_folder)
	if not os.path.isdir(args[0]):
		raise Exception(alert_not_dir % args[0])
except Exception as e:
	print(str(e))
	print(alert_example)
	sys.exit(2)

# adjustment storage name
storage = args[0] + storage

# perform initialization
if option_i:
	if os.path.isfile(storage):
		print(alert_dir_initialized % args[0])
		sys.exit(2)

	for path_file in glob(args[0] + '/**', recursive=True):
		if os.path.isfile(path_file):
			with open(path_file, 'r') as file:
				new_hash = encode(key, file.read().encode()).hexdigest()
			data[path_file] = new_hash
			print('adding:', path_file, '-', new_hash, file = output)

# perform tracking
elif option_t:
	if not os.path.isfile(storage):
		print(alert_dir_not_initialized % args[0])
		sys.exit(2)

	# load old data
	with open(storage, 'r') as file:
		old_data = json.loads(file.read())

	# checking for new and modified
	for path_file in glob(args[0] + '/**', recursive=True):
		if os.path.isfile(path_file):
			with open(path_file, 'r') as file:
				new_hash = encode(key, file.read().encode()).hexdigest()
			old_hash = old_data.get(path_file)
			data[path_file] = new_hash
			if old_hash:
				del old_data[path_file]
				if old_hash != new_hash:
					print('modifying:', path_file, '-', new_hash, file = output)
			else:
				print('adding:', path_file, '-', new_hash, file = output)

	# checking not found
	for path_file, old_hash in old_data.items():
		print('removing:', path_file, '-', old_hash, file = output)

# perform deactivation
elif option_x:
	if not os.path.isfile(storage):
		print(alert_dir_not_initialized % args[0])
		sys.exit(2)

	os.remove(storage)
	print('released folder: ' + args[0])

# save data
if data:
	with open(storage, 'w') as file:
		file.write(json.dumps(data))
output.close()
