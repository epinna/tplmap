import random
import string

def randint_n(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return random.randint(range_start, range_end)
    
def randstr_n(n):
    return ''.join(
        random.choice(string.letters + string.digits) for _ in range(n)
    )