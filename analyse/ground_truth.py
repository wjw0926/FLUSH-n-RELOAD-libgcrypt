# Get ground truth
def ground_truth(inputfile):
    with open(inputfile, mode='rb') as binary:
        content = binary.read()
        d_index = content.find('d256:')
        p_index = content.find('p129:')
        q_index = content.find('q129:')
        if inputfile == 'rsa_L1.sp':
            u_index = content.find('u129:')
        elif inputfile == 'rsa_L2.sp' or inputfile == 'rsa_L0.sp':
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
        #print ('Ground truth is ' + str(len(ground_truth)) + '-bit long')

    return ground_truth
