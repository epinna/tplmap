import random
import string

def randint_n(n):

    # If the length is 1, starts from 2 to avoid
    # number repetition on evaluation e.g. 1*8=8
    # creating false positives

    if n == 1:
        range_start = 2
    else:
        range_start = 10**(n-1)

    range_end = (10**n)-1
    return random.randint(range_start, range_end)

def randstr_n(n):
    return ''.join(
        random.choice(string.letters + string.digits) for _ in range(n)
    )
