from collections import namedtuple
from matplotlib import pyplot as plt
import sys
import csv

inputfile = sys.argv[1]
Row = namedtuple('Row', ['slot', 'addr', 'time'])
ylimit = 500

sqr_addr = [0,1]
mod_addr = [2]
mul_addr = [3,4]

data = {}

with open(inputfile, 'rb') as datafile:
    reader = csv.reader(datafile, delimiter=' ')
    rows = [Row(slot=int(row[0]), addr=int(row[1]), time=int(row[2])) for row in reader]

    for row in rows:
        if row.slot not in data:
            data[row.slot] = [0,0,0]
        if row.time < ylimit:
            if row.addr in sqr_addr:
                if data[row.slot][0] == 0 or data[row.slot][0] > row.time:
                    data[row.slot][0] = row.time
            elif row.addr in mod_addr:
                if data[row.slot][1] == 0 or data[row.slot][1] > row.time:
                    data[row.slot][1] = row.time
            elif row.addr in mul_addr:
                if data[row.slot][2] == 0 or data[row.slot][2] > row.time:
                    data[row.slot][2] = row.time

    plt.plot([slot for slot in data.keys()],
             [data[slot][0] for slot in data.keys()],
             'bo', label='Square')
    plt.plot([slot for slot in data.keys()],
             [data[slot][1] for slot in data.keys()],
             'g^', label='Modulo')
    plt.plot([slot for slot in data.keys()],
             [data[slot][2] for slot in data.keys()],
             'rx', label='Multiply')

    plt.xlabel('Time Slot Number')
    plt.ylabel('Probe Time (cycles)')
    plt.xlim(int(sys.argv[2]), int(sys.argv[3]))
    plt.ylim(0, ylimit)
    plt.legend()
    plt.show()
