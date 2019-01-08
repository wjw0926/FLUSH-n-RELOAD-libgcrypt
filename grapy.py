from collections import namedtuple
from matplotlib import pyplot as plt
import sys
import csv

inputfile = sys.argv[1]
Row = namedtuple('Row', ['slot', 'addr', 'time'])
threshold = 110

# Change addr variables depends on offset files
sqr_addr = [0,1]
mod_addr = [2]
mul_addr = [3,4,5,6]

square = []
modulo = []
multiply = []

with open(inputfile, 'rb') as datafile:
    reader = csv.reader(datafile, delimiter=' ')
    rows = [Row(slot=int(row[0]), addr=int(row[1]), time=int(row[2])) for row in reader]

    for row in rows:
        if row.time < threshold:
            if row.addr in sqr_addr:
                square.append(row)
            elif row.addr in mod_addr:
                modulo.append(row)
            elif row.addr in mul_addr:
                multiply.append(row)

    plt.plot([sqr_row.slot for sqr_row in square],
             [sqr_row.time for sqr_row in square],
             'bo', label='Square')
    plt.plot([mod_row.slot for mod_row in modulo],
             [mod_row.time for mod_row in modulo],
             'g^', label='Modulo')
    plt.plot([mul_row.slot for mul_row in multiply],
             [mul_row.time for mul_row in multiply],
             'rx', label='Multiply')

    plt.xlabel('Time Slot Number')
    plt.ylabel('Probe Time (cycles)')
    plt.legend()
    plt.show()
