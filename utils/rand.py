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

def randstr_n(n, chars=string.letters + string.digits):
    return ''.join(
        random.choice(chars) for _ in range(n)
    )

# Generate static random integers
# to help filling actions['render']
randints = [
    randint_n(2) for n in range(3)
]

# Generate static random integers
# to help filling actions['render']
randstrings = [
    randstr_n(2) for n in range(3)
]
