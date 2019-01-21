from collections import namedtuple
import sys
import csv

# Get ground truth
with open(sys.argv[2], mode='rb') as binary:
    content = binary.read()
    d_index = content.find('d256:')
    p_index = content.find('p129:')
    q_index = content.find('q129:')
    if sys.argv[2] == 'rsa_L1.sp':
        u_index = content.find('u129:')
    elif sys.argv[2] == 'rsa_L2.sp':
        u_index = content.find('u128:')

    d = 0
    p = 0
    q = 0

    for i in range(d_index+5, p_index-4):
        byte = int(bin(ord(content[i])), 2) & 0b11111111
        d = d * 256 + int(byte)

    for i in range(p_index+5, q_index-4):
        byte = int(bin(ord(content[i])), 2) & 0b11111111
        p = p * 256 + int(byte)

    for i in range(q_index+5, u_index-4):
        byte = int(bin(ord(content[i])), 2) & 0b11111111
        q = q * 256 + int(byte)

    d_p = d % (p-1)
    d_q = d % (q-1)

    ground_truth = str(bin(d_p))[2:] + str(bin(d_q)[2:])

    print (ground_truth)
    print ('Ground truth is ' + str(len(ground_truth)) + '-bit long')

# Read attack results
inputfile = sys.argv[1]
Row = namedtuple('Row', ['slot', 'addr', 'time'])
threshold = 85

sqr_addr = [0]
mod_addr = [1]
mul_addr = [2]

data = []       # [ [1,0,0], [0,1,0], ... ]
result = []     # [0, 0, 1, 0, 1, 1, 0, 1, ...]

with open(inputfile, 'rb') as datafile:
    reader = csv.reader(datafile, delimiter=' ')
    rows = [Row(slot=int(row[0]), addr=int(row[1]), time=int(row[2])) for row in reader]

    for i in xrange(0, len(rows), 3):
        element = [0, 0, 0]
        if rows[i].time < threshold:
            element[0] = 1
        if rows[i+1].time < threshold:
            element[1] = 1
        if rows[i+2].time < threshold:
            element[2] = 1
        data.append(element)

# State definition
start = 'START'
square = 'SQUARE'
modulo = 'MODULO'
modulo_r = 'MODULO_R'
multiply = 'MULTIPLY'
final_0 = 'FINAL_0'
final_1 = 'FINAL_1'

class Recover_Automata:
    def __init__(self):
        self.state = start

    def finish(self):
        self.__init__()
        return bit

    def transition(self, element):
        bit = ''

        if self.state == start:
            if element[0] == 1:
                self.state = square

        elif self.state == square:
            if element[0] == 1:
                self.state = square
            elif element[0] == 0 and element[1] == 1: # only modulo
                self.state = modulo

        elif self.state == modulo:
            if element[0] == 0 and element[1] == 1: # only modulo
                self.state = modulo
            elif element[0] == 1 and element[1] == 1:
                self.state = modulo_r
            elif element[0] == 1 and element[1] == 0: # only square
                bit = '0'
                self.state = square
            if element[2] == 1:
                self.state = multiply
        
        elif self.state == modulo_r:
            if element[0] == 1:
                bit = '0'
                self.state = square
            elif element[0] == 0 and element[1] == 1: # only modulo
                bit = '0'
                self.state = modulo
            if element[2] == 1:
                self.state = multiply
        
        elif self.state == multiply:
            if element[0] == 0 and element[1] == 1: # only modulo
                self.state = final_1
            if element[2] == 1:
                self.state = multiply
        
        elif self.state == final_1:
            if element[0] == 0 and element[1] == 1: # only modulo
                self.state = final_1
            elif element[0] == 1:
                bit = '1'
                self.state = square
        
        return bit

a = Recover_Automata()

for element in data:
    result.append(''.join(a.transition(element)))

cnt = 0
for i in result:
    if i == '1':
        del result[:cnt]
        break
    cnt = cnt + 1

recovered = ''.join(result)
print recovered
print ('Recovered secret is ' + str(len(recovered)) + '-bit long')

# Calculate recover rate
def lcs(s1, s2):
    matrix = [["" for x in range(len(s2))] for x in range(len(s1))]
    for i in range(len(s1)):
        for j in range(len(s2)):
            if s1[i] == s2[j]:
                if i == 0 or j == 0:
                    matrix[i][j] = s1[i]
                else:
                    matrix[i][j] = matrix[i-1][j-1] + s1[i]
            else:
                matrix[i][j] = max(matrix[i-1][j], matrix[i][j-1], key=len)

    cs = matrix[-1][-1]

    return cs

recover_rate = float(len(lcs(recovered, ground_truth))) / float(len(ground_truth))
print ('Recover rate is %.2f%%' % (recover_rate*100))
