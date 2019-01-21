from ground_truth import ground_truth
from translate import translate
from lcs import lcs
from numpy import median

import sys, os

rate_list = []
ground_truth = ground_truth('rsa_'+sys.argv[1]+'.sp')

for i in range(1, 1001):
    inputfile = os.path.join('../cross-VM/RSA/client/results/', 'result-100-'+str(i)+'.txt')
    recovered = translate(inputfile)

    recover_rate = float(len(lcs(recovered, ground_truth))) / float(len(ground_truth))
    rate_list.append(recover_rate)
    
    print ('Recover rate is %.2f%%' % (recover_rate*100))

Average = float(sum(rate_list)) / 1000
Median = median(rate_list)
Max = max(rate_list)

f= open("recover_rate.txt", "w+")

f.write('Average recover rate is %.2f%%\n' % (Average*100))
f.write('Median recover rate is %.2f%%\n' % (Median*100))
f.write('Maximum recover rate is %.2f%%\n' % (Max*100))

for i in range(1000):
    f.write("%.4f\n" % rate_list[i])

f.close()
