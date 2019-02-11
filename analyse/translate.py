from collections import namedtuple
import sys
import csv

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

# Translate attack result
def translate(inputfile):
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
    print ('Recovered secret is ' + str(len(recovered)) + '-bit long')

    return recovered
