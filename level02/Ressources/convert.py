import sys

str = ['756e505234376848', '45414a3561733951', '377a7143574e6758', '354a35686e475873', '48336750664b394d']

for part in str:
    sys.stdout.write(bytes.fromhex(part)[::-1].decode())
print()
